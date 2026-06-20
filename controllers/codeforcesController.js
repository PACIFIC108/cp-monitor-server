const { getProfile, getRecentSubmissions } = require('../services/codeforcesService');

const FINAL_VERDICTS = new Set([
    'OK',
    'WRONG_ANSWER',
    'TIME_LIMIT_EXCEEDED',
    'MEMORY_LIMIT_EXCEEDED',
    'COMPILATION_ERROR',
    'RUNTIME_ERROR',
    'IDLENESS_LIMIT_EXCEEDED',
    'SECURITY_VIOLATED',
    'CRASHED',
    'INPUT_PREPARATION_CRASHED',
    'CHALLENGED',
    'SKIPPED',
    'FAILED',
    'PARTIAL',
]);

const sendEvent = (res, event, data, id) => {
    if (id != null) res.write(`id: ${id}\n`);
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
};

exports.profile = async (req, res) => {
    const handle = req.params.handle?.trim();
    if (!handle || handle.length > 50) {
        return res.status(400).json({ message: 'Enter a valid Codeforces handle' });
    }
    const profile = await getProfile(handle);
    return res.status(200).json(profile);
};

exports.monitor = async (req, res) => {
    const { handle } = req.codeforcesUser;
    res.status(200);
    res.set({
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
    });
    res.flushHeaders();

    let stopped = false;
    let timer;
    let heartbeat;
    const announced = new Set();
    const pendingAtStart = new Set();
    let baselineId = 0;

    req.on('close', () => {
        stopped = true;
        clearTimeout(timer);
        clearInterval(heartbeat);
    });

    try {
        const initial = await getRecentSubmissions(handle, 20);
        const lastEventId = Number(req.get('Last-Event-ID')) || 0;
        baselineId = lastEventId || initial.reduce((max, item) => Math.max(max, item.id), 0);
        initial.forEach((submission) => {
            if (FINAL_VERDICTS.has(submission.verdict) && (!lastEventId || submission.id <= lastEventId)) {
                announced.add(submission.id);
            }
            else pendingAtStart.add(submission.id);
        });
        sendEvent(res, 'ready', { handle, message: 'Monitoring started' });
    } catch (error) {
        sendEvent(res, 'monitor-error', { message: error.message || 'Could not start monitoring' });
        return res.end();
    }

    heartbeat = setInterval(() => {
        if (!stopped) res.write(': heartbeat\n\n');
    }, 15000);

    const poll = async () => {
        if (stopped) return;
        try {
            const submissions = await getRecentSubmissions(handle, 20);
            const completed = submissions
                .filter((item) => FINAL_VERDICTS.has(item.verdict))
                .filter((item) => !announced.has(item.id))
                .filter((item) => item.id > baselineId || pendingAtStart.has(item.id))
                .sort((a, b) => a.id - b.id);

            completed.forEach((submission) => {
                announced.add(submission.id);
                pendingAtStart.delete(submission.id);
                sendEvent(res, 'verdict', {
                    id: submission.id,
                    verdict: submission.verdict,
                    creationTimeSeconds: submission.creationTimeSeconds,
                    problem: submission.problem,
                }, submission.id);
            });
        } catch (error) {
            sendEvent(res, 'monitor-error', {
                message: error.message || 'Codeforces polling failed; retrying',
            });
        } finally {
            if (!stopped) timer = setTimeout(poll, 7000);
        }
    };

    timer = setTimeout(poll, 2000);
};
