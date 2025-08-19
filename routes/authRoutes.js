const express = require('express');
const { authorizeUser, callback, verifyUser, loginUser, signupUser, logoutUser, checkAuth, logoutApp } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/login', loginUser);
router.post('/signup', signupUser);
router.post('/logoutUser', logoutUser);
router.post('/logout', logoutApp);
router.get('/checkAuth', protect, checkAuth);
router.get('/authLogin', authorizeUser);
router.get('/callback', callback);
router.get('/me', verifyUser);

module.exports = router;
