const axios = require('axios');

const client = axios.create({
    baseURL: 'https://codeforces.com',
    timeout: 10000,
});

let requestQueue = Promise.resolve();
let lastRequestAt = 0;

const request = (path, params) => {
    const task = requestQueue.then(async () => {
        const waitMs = Math.max(0, 2100 - (Date.now() - lastRequestAt));
        if (waitMs) await new Promise((resolve) => setTimeout(resolve, waitMs));
        try {
            return await client.get(path, { params });
        } finally {
            lastRequestAt = Date.now();
        }
    });
    requestQueue = task.catch(() => {});
    return task;
};

const unwrap = (response) => {
    if (response.data?.status !== 'OK') {
        const error = new Error(response.data?.comment || 'Codeforces request failed');
        error.status = 502;
        throw error;
    }
    return response.data.result;
};

const getProfile = async (handle) => {
    const response = await request('/api/user.info', { handles: handle });
    return unwrap(response)[0];
};

const getRecentSubmissions = async (handle, count = 10) => {
    const response = await request('/api/user.status', { handle, from: 1, count });
    return unwrap(response);
};

const getSubmissionHistory = async (handle) => getRecentSubmissions(handle, 10000);

const getRatingHistory = async (handle) => {
    const response = await request('/api/user.rating', { handle });
    return unwrap(response);
};

module.exports = { getProfile, getRecentSubmissions, getSubmissionHistory, getRatingHistory };
