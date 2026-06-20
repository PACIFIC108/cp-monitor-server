const mongoose = require('mongoose');

const codeforcesProfileSchema = new mongoose.Schema({
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    subject: { type: String, required: true, unique: true, index: true },
    handle: { type: String, required: true, trim: true },
    rating: Number,
    maxRating: Number,
    rank: String,
    maxRank: String,
    friendOfCount: Number,
    contribution: Number,
    avatar: String,
    titlePhoto: String,
    linkedAt: { type: Date, default: Date.now },
    lastSyncedAt: Date,
}, { timestamps: true });

codeforcesProfileSchema.index({ owner: 1, subject: 1 }, { unique: true });

module.exports = mongoose.model('CodeforcesProfile', codeforcesProfileSchema);
