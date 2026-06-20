const express = require('express');
const controller = require('../controllers/authController');
const { protect, protectCodeforces } = require('../middleware/authMiddleware');
const asyncHandler = require('../utils/asyncHandler');

const router = express.Router();

router.post('/login', asyncHandler(controller.loginUser));
router.post('/signup', asyncHandler(controller.signupUser));
router.post('/logoutUser', controller.logoutUser);
router.post('/logout', controller.logoutApp);
router.get('/checkAuth', asyncHandler(protect), controller.checkAuth);
router.get('/authLogin', asyncHandler(protect), asyncHandler(controller.authorizeUser));
router.get('/callback', asyncHandler(protect), asyncHandler(controller.callback));
router.get('/me', protectCodeforces, controller.verifyUser);

module.exports = router;
