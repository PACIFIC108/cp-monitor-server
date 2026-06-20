const jwt = require('jsonwebtoken');
const config = require('../config/env');

const generateToken = (res, userId) => {
    const token = jwt.sign(
        { userId: userId.toString(), type: 'app' },
        config.jwtSecret,
        { expiresIn: '10h' },
    );
    res.cookie('token', token, config.cookieOptions(10 * 60 * 60 * 1000));
};

module.exports = generateToken;
