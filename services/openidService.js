const crypto = require('crypto');
const config = require('../config/env');

let metadataPromise;
let jwksPromise;

const fetchJson = async (url, label) => {
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error(`Could not load Codeforces ${label}`);
    return response.json();
};

const getMetadata = async () => {
    if (!metadataPromise) {
        metadataPromise = fetchJson(
            `${config.codeforces.issuer}/.well-known/openid-configuration`,
            'OpenID configuration',
        ).catch((error) => {
            metadataPromise = null;
            throw error;
        });
    }
    return metadataPromise;
};

const decodePart = (value) => JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));

const verifyHmacSignature = (signingInput, encodedSignature) => {
    if (!config.codeforces.clientSecret) throw new Error('Codeforces client secret is not configured');
    const expected = crypto
        .createHmac('sha256', config.codeforces.clientSecret)
        .update(signingInput)
        .digest();
    const received = Buffer.from(encodedSignature, 'base64url');
    return expected.length === received.length && crypto.timingSafeEqual(expected, received);
};

const verifyRsaSignature = async (header, signingInput, encodedSignature, metadata) => {
    if (!header.kid || !metadata.jwks_uri) return false;
    if (!jwksPromise) {
        jwksPromise = fetchJson(metadata.jwks_uri, 'signing keys').catch((error) => {
            jwksPromise = null;
            throw error;
        });
    }
    const jwks = await jwksPromise;
    const jwk = jwks.keys?.find((key) => key.kid === header.kid && key.kty === 'RSA');
    if (!jwk) {
        jwksPromise = null;
        throw new Error('No matching Codeforces signing key');
    }
    return crypto.verify(
        'RSA-SHA256',
        Buffer.from(signingInput),
        crypto.createPublicKey({ key: jwk, format: 'jwk' }),
        Buffer.from(encodedSignature, 'base64url'),
    );
};

const verifyIdToken = async (idToken, expectedNonce) => {
    const parts = idToken.split('.');
    if (parts.length !== 3) throw new Error('Malformed Codeforces ID token');
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const header = decodePart(encodedHeader);
    const payload = decodePart(encodedPayload);
    const metadata = await getMetadata();

    const signingInput = `${encodedHeader}.${encodedPayload}`;
    let verified;
    if (header.alg === 'HS256') {
        verified = verifyHmacSignature(signingInput, encodedSignature);
    } else if (header.alg === 'RS256') {
        verified = await verifyRsaSignature(header, signingInput, encodedSignature, metadata);
    } else {
        throw new Error(`Unsupported ID token signature algorithm: ${header.alg || 'missing'}`);
    }
    if (!verified) throw new Error('Invalid Codeforces ID token signature');

    const now = Math.floor(Date.now() / 1000);
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (payload.iss !== metadata.issuer) throw new Error('Invalid ID token issuer');
    if (!audiences.includes(config.codeforces.clientId)) throw new Error('Invalid ID token audience');
    if (audiences.length > 1 && payload.azp !== config.codeforces.clientId) {
        throw new Error('Invalid ID token authorized party');
    }
    if (!payload.exp || payload.exp <= now) throw new Error('Expired ID token');
    if (payload.nbf && payload.nbf > now + 30) throw new Error('ID token is not active');
    if (payload.iat && payload.iat > now + 30) throw new Error('ID token was issued in the future');
    if (!payload.nonce || payload.nonce !== expectedNonce) throw new Error('Invalid OAuth nonce');
    return payload;
};

module.exports = { getMetadata, verifyIdToken };
