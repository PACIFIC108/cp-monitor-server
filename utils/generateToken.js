const jwt = require('jsonwebtoken');

const generateToken = (res, userId) => {
    const token = jwt.sign({ Id: userId }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
        httpOnly: true,          // secure, not accessible via JS
        secure: true,            // must be HTTPS on both frontend & backend
        sameSite: 'none',
        maxAge: 7*24*60*60*1000
    });
};

module.exports = generateToken;
