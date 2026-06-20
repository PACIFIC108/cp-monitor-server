const crypto = require('crypto');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const config = require('../config/env');
const generateToken = require('../utils/generateToken');
const { clearCookie } = require('../utils/cookies');
const { validateCredentials } = require('../utils/validation');
const { getProfile } = require('../services/codeforcesService');
const { getMetadata, verifyIdToken } = require('../services/openidService');
const AnalyticsSnapshot = require('../models/analyticsSnapshotModel');
const ContestResult = require('../models/contestResultModel');
const CodeforcesProfile = require('../models/codeforcesProfileModel');

const publicUser = (user) => ({
    id: user._id,
    userName: user.userName,
    email: user.email,
    codeforcesHandle: user.codeforces?.handle || null,
    activeCodeforcesProfile: user.activeCodeforcesProfile || null,
});

exports.loginUser = async (req, res) => {
    const { errors, normalized } = validateCredentials(req.body);
    if (errors.length) return res.status(400).json({ message: errors[0], errors });

    const user = await User.findOne({ userName: normalized.userName }).select('+password');
    if (!user || !(await bcrypt.compare(normalized.password, user.password))) {
        return res.status(401).json({ message: 'Wrong username or password' });
    }

    generateToken(res, user._id);
    return res.status(200).json({ message: 'Login successful', user: publicUser(user) });
};

exports.signupUser = async (req, res) => {
    const { errors, normalized } = validateCredentials(req.body, true);
    if (errors.length) return res.status(400).json({ message: errors[0], errors });

    const existing = await User.findOne({
        $or: [{ email: normalized.email }, { userName: normalized.userName }],
    });
    if (existing) {
        const field = existing.email === normalized.email ? 'Email' : 'Username';
        return res.status(409).json({ message: `${field} is already taken` });
    }

    try {
        const user = await User.create({
            email: normalized.email,
            userName: normalized.userName,
            password: await bcrypt.hash(normalized.password, 12),
        });
        generateToken(res, user._id);
        return res.status(201).json({ message: 'Signup successful', user: publicUser(user) });
    } catch (error) {
        if (error?.code === 11000) {
            return res.status(409).json({ message: 'Email or username is already taken' });
        }
        throw error;
    }
};

exports.logoutApp = (req, res) => {
    clearCookie(res, 'token');
    clearCookie(res, 'session');
    return res.status(200).json({ message: 'Logout successful' });
};

exports.logoutUser = (req, res) => {
    clearCookie(res, 'session');
    return res.status(200).json({ message: 'Codeforces account disconnected' });
};

exports.checkAuth = (req, res) => {
    return res.status(200).json({ user: publicUser(req.user) });
};

exports.authorizeUser = async (req, res) => {
    const { clientId, clientSecret, redirectUri } = config.codeforces;
    if (!clientId || !clientSecret || !redirectUri) {
        return res.status(503).json({ message: 'Codeforces OAuth is not configured' });
    }

    const metadata = await getMetadata();
    const state = crypto.randomBytes(32).toString('hex');
    const nonce = crypto.randomBytes(32).toString('hex');
    const shortCookie = config.cookieOptions(10 * 60 * 1000);
    res.cookie('oauth_state', state, shortCookie);
    res.cookie('oauth_nonce', nonce, shortCookie);

    const params = new URLSearchParams({
        response_type: 'code',
        scope: 'openid',
        client_id: clientId,
        redirect_uri: redirectUri,
        state,
        nonce,
    });
    return res.redirect(`${metadata.authorization_endpoint}?${params}`);
};

exports.callback = async (req, res) => {
    const { code, state } = req.query;
    if (!code || !state || state !== req.cookies.oauth_state) {
        return res.status(400).send('Invalid OAuth callback');
    }

    const metadata = await getMetadata();
    const response = await axios.post(metadata.token_endpoint, new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: config.codeforces.clientId,
        client_secret: config.codeforces.clientSecret,
        redirect_uri: config.codeforces.redirectUri,
    }), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 10000,
    });

    if (!response.data?.id_token) throw new Error('Codeforces did not return an ID token');
    const claims = await verifyIdToken(response.data.id_token, req.cookies.oauth_nonce);
    if (!claims.handle || !claims.sub) throw new Error('Codeforces token is missing required identity claims');

    const profile = await getProfile(claims.handle);
    let linkedProfile = await CodeforcesProfile.findOne({ subject: claims.sub });
    if (linkedProfile && linkedProfile.owner.toString() !== req.user._id.toString()) {
        return res.status(409).send('This Codeforces account is already linked to another account');
    }
    const profileData = {
        owner: req.user._id,
        subject: claims.sub,
        handle: profile.handle,
        rating: profile.rating,
        maxRating: profile.maxRating,
        rank: profile.rank,
        maxRank: profile.maxRank,
        friendOfCount: profile.friendOfCount,
        contribution: profile.contribution,
        avatar: profile.avatar,
        titlePhoto: profile.titlePhoto,
    };
    if (linkedProfile) {
        Object.assign(linkedProfile, profileData);
        await linkedProfile.save();
    } else {
        linkedProfile = await CodeforcesProfile.create(profileData);
    }

    await Promise.all([
        AnalyticsSnapshot.updateMany(
            { user: req.user._id, profile: { $exists: false }, handle: profile.handle },
            { $set: { profile: linkedProfile._id } },
        ),
        ContestResult.updateMany(
            { user: req.user._id, profile: { $exists: false }, handle: profile.handle },
            { $set: { profile: linkedProfile._id } },
        ),
    ]);
    req.user.codeforces = {
        subject: claims.sub,
        handle: profile.handle,
        linkedAt: req.user.codeforces?.linkedAt || new Date(),
        lastSyncedAt: req.user.codeforces?.lastSyncedAt,
    };
    req.user.activeCodeforcesProfile = linkedProfile._id;
    await req.user.save();
    const sessionProfile = {
        handle: profile.handle,
        rating: profile.rating,
        maxRating: profile.maxRating,
        rank: profile.rank,
        maxRank: profile.maxRank,
        friendOfCount: profile.friendOfCount,
        contribution: profile.contribution,
        avatar: profile.avatar,
        titlePhoto: profile.titlePhoto,
        subject: claims.sub,
    };
    const sessionToken = jwt.sign(
        { ...sessionProfile, type: 'codeforces' },
        config.jwtSecret,
        { expiresIn: '7d' },
    );

    res.cookie('session', sessionToken, config.cookieOptions(7 * 24 * 60 * 60 * 1000));
    clearCookie(res, 'oauth_state');
    clearCookie(res, 'oauth_nonce');
    return res.redirect(`${config.clientUrl}/app`);
};

exports.verifyUser = (req, res) => {
    return res.status(200).json(req.codeforcesUser);
};
