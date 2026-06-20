require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');
const config = require('./config/env');
const authRoutes = require('./routes/authRoutes');
const codeforcesRoutes = require('./routes/codeforcesRoutes');
const analyticsRoutes = require('./routes/analyticsRoutes');

const app = express();

app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());
app.use(cors({
    origin(origin, callback) {
        if (!origin || config.clientUrls.includes(origin.replace(/\/$/, ''))) return callback(null, true);
        return callback(new Error('Origin is not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Last-Event-ID'],
}));

app.use('/api', rateLimit({
    windowMs: 60 * 1000,
    limit: 120,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { message: 'Too many requests, try again later' },
}));

app.use('/api/auth', authRoutes);
app.use('/api/codeforces', codeforcesRoutes);
app.use('/api/analytics', analyticsRoutes);

app.get('/', (_req, res) => res.status(200).send('Backend is running'));

app.use((req, res) => res.status(404).json({ message: 'Route not found' }));
app.use((error, _req, res, _next) => {
    console.error(error);
    const upstreamMessage = error.response?.data?.comment || error.response?.data?.message;
    const status = error.status || (error.response ? 502 : 500);
    res.status(status).json({ message: upstreamMessage || error.message || 'Server error' });
});

connectDB().then(() => {
    app.listen(config.port, () => console.log(`Server running on port ${config.port}`));
});

module.exports = app;
