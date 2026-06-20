const required = ['MONGO_URI', 'JWT_SECRET', 'CLIENT_URL'];

const missing = required.filter((key) => !process.env[key]);
if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
}

const isProduction = process.env.NODE_ENV === 'production';
const crossSiteCookies = process.env.CROSS_SITE_COOKIES === 'true';

const clientUrls = process.env.CLIENT_URL
    .split(',')
    .map((url) => url.trim().replace(/\/$/, ''))
    .filter(Boolean);

const cookieOptions = (maxAge) => ({
    httpOnly: true,
    secure: isProduction || crossSiteCookies,
    sameSite: crossSiteCookies ? 'none' : 'lax',
    ...(process.env.COOKIE_DOMAIN ? { domain: process.env.COOKIE_DOMAIN } : {}),
    path: '/',
    ...(maxAge ? { maxAge } : {}),
});

module.exports = {
    port: Number(process.env.PORT) || 3000,
    mongoUri: process.env.MONGO_URI,
    jwtSecret: process.env.JWT_SECRET,
    clientUrls,
    clientUrl: clientUrls[0],
    cookieOptions,
    codeforces: {
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        redirectUri: process.env.CF_REDIRECT_URI,
        issuer: process.env.CF_ISSUER || 'https://codeforces.com',
    },
};
