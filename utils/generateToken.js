const jwt = require('jsonwebtoken');

const generateToken = (res, userId) => {
    const token = jwt.sign({ Id: userId }, process.env.JWT_SECRET, { expiresIn: '10h' });

    res.cookie('token', token, {
        httpOnly: true,
        sameSite: "none",
        secure: process.env.NODE_ENV === "production",
    });
};

module.exports = generateToken;
