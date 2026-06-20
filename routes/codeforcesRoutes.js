const express = require('express');
const controller = require('../controllers/codeforcesController');
const { protect, protectCodeforces } = require('../middleware/authMiddleware');
const asyncHandler = require('../utils/asyncHandler');

const router = express.Router();

router.get('/profile/:handle', asyncHandler(protect), asyncHandler(controller.profile));
router.get('/monitor', asyncHandler(protect), protectCodeforces, asyncHandler(controller.monitor));

module.exports = router;
