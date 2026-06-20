const AnalyticsSnapshot = require('../models/analyticsSnapshotModel');
const ContestResult = require('../models/contestResultModel');
const User = require('../models/userModel');
const CodeforcesProfile = require('../models/codeforcesProfileModel');
const { getProfile, getSubmissionHistory, getRatingHistory } = require('./codeforcesService');

const dayKey = (seconds) => new Date(seconds * 1000).toISOString().slice(0, 10);
const problemKey = (problem = {}) => `${problem.contestId || problem.problemsetName || 'unknown'}:${problem.index || problem.name}`;
const isJudged = (verdict) => verdict && verdict !== 'TESTING';

const buildSnapshots = (submissions, ratings) => {
    const ratingByDay = new Map(ratings.map((item) => [dayKey(item.ratingUpdateTimeSeconds), item.newRating]));
    const ordered = [...submissions].sort((a, b) => a.creationTimeSeconds - b.creationTimeSeconds);
    const solved = new Set();
    const daily = new Map();
    let totalSubmissions = 0;
    let judgedSubmissions = 0;
    let acceptedSubmissions = 0;
    let wrongAnswers = 0;
    let currentRating;

    ordered.forEach((submission) => {
        const key = dayKey(submission.creationTimeSeconds);
        totalSubmissions += 1;
        if (isJudged(submission.verdict)) judgedSubmissions += 1;
        if (submission.verdict === 'OK') {
            acceptedSubmissions += 1;
            solved.add(problemKey(submission.problem));
        }
        if (submission.verdict === 'WRONG_ANSWER') wrongAnswers += 1;
        if (ratingByDay.has(key)) currentRating = ratingByDay.get(key);

        daily.set(key, {
            dayKey: key,
            date: new Date(`${key}T00:00:00.000Z`),
            solvedCount: solved.size,
            totalSubmissions,
            judgedSubmissions,
            acceptedSubmissions,
            wrongAnswers,
            wrongAnswerRate: judgedSubmissions ? Number(((wrongAnswers / judgedSubmissions) * 100).toFixed(2)) : 0,
            rating: currentRating,
        });
    });

    return [...daily.values()].slice(-365);
};

const syncLocks = new Map();

const performSync = async (userId, linkedProfile) => {
    const codeforcesProfile = await getProfile(linkedProfile.handle);
    const submissions = await getSubmissionHistory(codeforcesProfile.handle);
    const ratings = await getRatingHistory(codeforcesProfile.handle);
    const snapshots = buildSnapshots(submissions, ratings);

    if (snapshots.length) {
        await AnalyticsSnapshot.bulkWrite(snapshots.map((snapshot) => ({
            updateOne: {
                filter: { profile: linkedProfile._id, dayKey: snapshot.dayKey },
                update: { $set: { ...snapshot, user: userId, profile: linkedProfile._id, handle: codeforcesProfile.handle } },
                upsert: true,
            },
        })));
    }

    if (ratings.length) {
        await ContestResult.bulkWrite(ratings.map((contest) => ({
            updateOne: {
                filter: { profile: linkedProfile._id, contestId: contest.contestId },
                update: { $set: {
                    user: userId,
                    profile: linkedProfile._id,
                    handle: codeforcesProfile.handle,
                    contestId: contest.contestId,
                    contestName: contest.contestName,
                    rank: contest.rank,
                    oldRating: contest.oldRating,
                    newRating: contest.newRating,
                    ratingChange: contest.newRating - contest.oldRating,
                    ratedAt: new Date(contest.ratingUpdateTimeSeconds * 1000),
                } },
                upsert: true,
            },
        })));
    }

    const syncedAt = new Date();
    await Promise.all([
        CodeforcesProfile.findByIdAndUpdate(linkedProfile._id, {
            $set: {
                handle: codeforcesProfile.handle,
                rating: codeforcesProfile.rating,
                maxRating: codeforcesProfile.maxRating,
                rank: codeforcesProfile.rank,
                maxRank: codeforcesProfile.maxRank,
                friendOfCount: codeforcesProfile.friendOfCount,
                contribution: codeforcesProfile.contribution,
                avatar: codeforcesProfile.avatar,
                titlePhoto: codeforcesProfile.titlePhoto,
                lastSyncedAt: syncedAt,
            },
        }),
        User.findByIdAndUpdate(userId, {
            $set: {
                activeCodeforcesProfile: linkedProfile._id,
                'codeforces.handle': codeforcesProfile.handle,
                'codeforces.lastSyncedAt': syncedAt,
            },
        }),
    ]);
    return getAnalytics(userId, linkedProfile._id);
};

const syncAnalytics = (userId, linkedProfile) => {
    const key = linkedProfile._id.toString();
    if (syncLocks.has(key)) return syncLocks.get(key);
    const task = performSync(userId, linkedProfile).finally(() => syncLocks.delete(key));
    syncLocks.set(key, task);
    return task;
};

const getAnalytics = async (userId, profileId) => {
    const [snapshots, contests, profile] = await Promise.all([
        AnalyticsSnapshot.find({ user: userId, profile: profileId }).sort({ date: 1 }).lean(),
        ContestResult.find({ user: userId, profile: profileId }).sort({ ratedAt: 1 }).lean(),
        CodeforcesProfile.findOne({ _id: profileId, owner: userId }).lean(),
    ]);
    const latest = snapshots.at(-1) || null;
    const latestContest = contests.at(-1) || null;
    return {
        handle: profile?.handle,
        profileId,
        lastSyncedAt: profile?.lastSyncedAt,
        summary: {
            solvedCount: latest?.solvedCount || 0,
            wrongAnswerRate: latest?.wrongAnswerRate || 0,
            totalSubmissions: latest?.totalSubmissions || 0,
            contests: contests.length,
            rating: latestContest?.newRating ?? latest?.rating ?? null,
            latestRank: latestContest?.rank ?? null,
        },
        snapshots,
        contests,
    };
};

module.exports = { getAnalytics, syncAnalytics };
