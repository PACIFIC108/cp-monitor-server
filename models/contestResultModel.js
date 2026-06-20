const mongoose = require('mongoose');

const contestResultSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    profile: { type: mongoose.Schema.Types.ObjectId, ref: 'CodeforcesProfile', required: true, index: true },
    handle: { type: String, required: true },
    contestId: { type: Number, required: true },
    contestName: { type: String, required: true },
    rank: { type: Number, required: true },
    oldRating: Number,
    newRating: Number,
    ratingChange: Number,
    ratedAt: { type: Date, required: true },
}, { timestamps: true });

contestResultSchema.index(
    { profile: 1, contestId: 1 },
    { unique: true, partialFilterExpression: { profile: { $type: 'objectId' } } },
);

module.exports = mongoose.model('ContestResult', contestResultSchema);
