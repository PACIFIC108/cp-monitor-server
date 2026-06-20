const config = require('../config/env');

const clearCookie = (res, name) => {
    res.clearCookie(name, config.cookieOptions());
};

module.exports = { clearCookie };
