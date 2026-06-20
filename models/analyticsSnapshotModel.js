const mongoose = require('mongoose');

const analyticsSnapshotSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    profile: { type: mongoose.Schema.Types.ObjectId, ref: 'CodeforcesProfile', required: true, index: true },
    handle: { type: String, required: true },
    date: { type: Date, required: true },
    dayKey: { type: String, required: true },
    solvedCount: { type: Number, required: true, default: 0 },
    totalSubmissions: { type: Number, required: true, default: 0 },
    judgedSubmissions: { type: Number, required: true, default: 0 },
    acceptedSubmissions: { type: Number, required: true, default: 0 },
    wrongAnswers: { type: Number, required: true, default: 0 },
    wrongAnswerRate: { type: Number, required: true, default: 0 },
    rating: Number,
}, { timestamps: true });

analyticsSnapshotSchema.index(
    { profile: 1, dayKey: 1 },
    { unique: true, partialFilterExpression: { profile: { $type: 'objectId' } } },
);

module.exports = mongoose.model('AnalyticsSnapshot', analyticsSnapshotSchema);
