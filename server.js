const dotenv = require('dotenv');
dotenv.config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');

connectDB();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
    // methods: "GET,POST,PUT,DELETE,OPTIONS",
    // allowedHeaders: "Content-Type,Authorization"
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60,
    message: 'Too many requests, try again later.'
});
app.use('/api', limiter);

// Routes
app.use('/api/auth', authRoutes);

app.get('/', (req, res) => {
    res.send('Backend is running...');
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
