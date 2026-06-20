const mongoose = require('mongoose');
const config = require('./env');

const connectDB = async () => {
    try {
        await mongoose.connect(config.mongoUri);
        const indexModels = ['CodeforcesProfile', 'AnalyticsSnapshot', 'ContestResult']
            .filter((name) => mongoose.models[name])
            .map((name) => mongoose.model(name).syncIndexes());
        await Promise.all(indexModels);
        console.log('MongoDB connected');
    } catch (error) {
        console.error('MongoDB connection failed', error);
        process.exit(1);
    }
};

module.exports = connectDB;
