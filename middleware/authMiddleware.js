const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const config = require('../config/env');

exports.protect = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: 'Not authorized' });

    try {
        const decoded = jwt.verify(token, config.jwtSecret);
        if (decoded.type !== 'app') throw new Error('Wrong token type');
        req.user = await User.findById(decoded.userId);
        if (!req.user) return res.status(401).json({ message: 'User not found' });
        return next();
    } catch (_) {
        return res.status(401).json({ message: 'Invalid or expired session' });
    }
};

exports.protectCodeforces = (req, res, next) => {
    const token = req.cookies.session;
    if (!token) return res.status(401).json({ message: 'Codeforces account is not connected' });

    try {
        const decoded = jwt.verify(token, config.jwtSecret);
        if (decoded.type !== 'codeforces' || !decoded.handle) throw new Error('Wrong token type');
        req.codeforcesUser = {
            handle: decoded.handle,
            rating: decoded.rating,
            maxRating: decoded.maxRating,
            rank: decoded.rank,
            maxRank: decoded.maxRank,
            friendOfCount: decoded.friendOfCount,
            contribution: decoded.contribution,
            avatar: decoded.avatar,
            titlePhoto: decoded.titlePhoto,
        };
        return next();
    } catch (_) {
        return res.status(401).json({ message: 'Invalid or expired Codeforces session' });
    }
};
