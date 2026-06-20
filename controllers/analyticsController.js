const CodeforcesProfile = require('../models/codeforcesProfileModel');
const { getAnalytics, syncAnalytics } = require('../services/analyticsService');

const getActiveProfile = async (user) => {
    let profile = user.activeCodeforcesProfile
        ? await CodeforcesProfile.findOne({ _id: user.activeCodeforcesProfile, owner: user._id })
        : null;
    if (!profile && user.codeforces?.subject) {
        profile = await CodeforcesProfile.findOne({ subject: user.codeforces.subject, owner: user._id });
        if (profile) {
            user.activeCodeforcesProfile = profile._id;
            await user.save();
        }
    }
    return profile;
};

exports.get = async (req, res) => {
    const profile = await getActiveProfile(req.user);
    if (!profile) {
        return res.status(409).json({ message: 'Connect your Codeforces account to view analytics' });
    }
    return res.status(200).json(await getAnalytics(req.user._id, profile._id));
};

exports.sync = async (req, res) => {
    const profile = await getActiveProfile(req.user);
    if (!profile) {
        return res.status(409).json({ message: 'Connect your Codeforces account before syncing analytics' });
    }
    const lastSync = profile.lastSyncedAt?.getTime() || 0;
    if (!req.body?.force && Date.now() - lastSync < 15 * 60 * 1000) {
        return res.status(200).json(await getAnalytics(req.user._id, profile._id));
    }
    return res.status(200).json(await syncAnalytics(req.user._id, profile));
};
