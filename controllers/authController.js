const User = require('../models/usermodel');
const bcrypt = require('bcryptjs');
const generateToken = require('../utils/generateToken');
const axios = require("axios");
const jwt = require("jsonwebtoken");
require('dotenv').config();

const {
    CLIENT_ID,
    CLIENT_SECRET,
    CF_REDIRECT_URI,
    JWT_SECRET,
    CLIENT_URL,
} = process.env;


exports.loginUser = async (req, res) => {
    try {
        const { userName, password } = req.body;
        if (!userName?.trim() || !password?.trim()) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        const user = await User.findOne({ userName });
        if (!user) return res.status(400).json({ message: 'Wrong credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Wrong credentials' });

        generateToken(res, user._id);
        return res.status(201).json({ message: 'Login successful', user: { id: user._id, userName: user.userName, email: user.email } });
    } catch (err) {
        console.error("Login Error:", err);
        return res.status(500).json({ message: 'Server error' });
    }
};

exports.signupUser = async (req, res) => {
    try {
        const { email, userName, password } = req.body;

        if (!email?.trim() || !userName?.trim() || !password?.trim()) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const isPresent = await User.findOne({ $or: [{ email }, { userName }] });
        if (isPresent) {
            if (isPresent.email === email && isPresent.userName === userName) {
                return res.status(400).json({ message: 'Both Email and Username are already taken' });
            }
            if (isPresent.email === email) {
                return res.status(400).json({ message: 'Email is already taken' });
            }
            return res.status(400).json({ message: 'Username is already taken' });
        }

        const hash = await bcrypt.hash(password, 10);
        const user = await User.create({ email, userName, password: hash });

        generateToken(res, user._id);
        return res.status(201).json({ message: 'Signup successful', user: { id: user._id, userName: user.userName, email: user.email } });
    } catch (err) {
        console.error("Signup Error:", err);
        return res.status(500).json({ message: 'Server error' });
    }
};

exports.logoutUser = (req, res) => {
    res.cookie('session', '', { httpOnly: true, expires: new Date(0) });
    return res.json({ message: 'Logout successful' });
};

exports.logoutApp = (req, res) => {
    res.cookie('token', '', { httpOnly: true, expires: new Date(0) });
    return res.json({ message: 'Logout successful' });
};

exports.checkAuth = (req, res) => {
    return res.status(201).json({ message: 'Authenticated', user: req.user });
};

exports.authorizeUser = (req, res) => {
    const authUrl = `https://codeforces.com/oauth/authorize?response_type=code&scope=openid&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(CF_REDIRECT_URI)}`;
    res.redirect(authUrl);
};

exports.callback = async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send("❌ No code provided");


    try {
        const { data } = await axios.post("https://codeforces.com/oauth/token", null, {
            params: {
                grant_type: "authorization_code",
                code,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uri: CF_REDIRECT_URI,
            },
        });
        const { id_token, access_token } = data;

        if (!id_token && !access_token) return res.status(400).send("❌ No ID token received");

        const claims = jwt.decode(id_token);
        let { handle } = claims || {};

        const resp = await axios.get(
            `https://codeforces.com/api/user.info?handles=${handle || ""}`
        );
        const user = resp.data.result[0];
                
        
        const sessionToken = jwt.sign( user, JWT_SECRET, {
            expiresIn: "7d",
        });

        res.cookie("session", sessionToken, {
            httpOnly: true,
            sameSite: "none",
            secure: process.env.NODE_ENV === "production",
              domain: ".onrender.com", 
              path: "/",
        });

        res.redirect(CLIENT_URL + "/app");
    } catch (err) {
        console.error("OAuth Error:", err.response?.data || err.message);
        res.status(500).send("❌ Authentication failed");
    }
};

exports.verifyUser = (req, res) => {
    const token = req.cookies.session;
    if (!token) return res.status(401).send("Not authenticated");

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.status(201).json(decoded);
    } catch (err) {
        res.status(401).send("Invalid session");
    }
};
