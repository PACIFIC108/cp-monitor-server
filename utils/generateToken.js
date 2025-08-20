const jwt = require('jsonwebtoken');

const generateToken = (res, userId) => {
    const token = jwt.sign({ Id: userId }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.cookie('token', token, {
        httpOnly: true,
        sameSite: "strict",
        secure: true,
        maxAge: 7*24*60*60*1000
    });
};

module.exports = generateToken;
