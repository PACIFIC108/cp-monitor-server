const normalizeEmail = (value = '') => value.trim().toLowerCase();
const normalizeUserName = (value = '') => value.trim().toLowerCase();

const validateCredentials = ({ email, userName, password }, requireEmail = false) => {
    const errors = [];
    const normalized = {
        email: normalizeEmail(email),
        userName: normalizeUserName(userName),
        password: typeof password === 'string' ? password : '',
    };

    if (requireEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized.email)) {
        errors.push('Enter a valid email address');
    }
    if (!/^[a-z0-9_]{3,30}$/.test(normalized.userName)) {
        errors.push('Username must be 3-30 characters and contain only letters, numbers, or underscores');
    }
    if (!normalized.password) {
        errors.push('Password is required');
    } else if (requireEmail && !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,72}$/.test(normalized.password)) {
        errors.push('Password must be 8-72 characters with uppercase, lowercase, and a number');
    }

    return { errors, normalized };
};

module.exports = { normalizeEmail, normalizeUserName, validateCredentials };
