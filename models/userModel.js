const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    userName: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
    },
    password: {
        type: String,
        required: true,
        select: false,
    },
    codeforces: {
        subject: { type: String, unique: true, sparse: true },
        handle: { type: String, trim: true },
        linkedAt: Date,
        lastSyncedAt: Date,
    },
    activeCodeforcesProfile: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'CodeforcesProfile',
        default: null,
    },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
