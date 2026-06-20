const express = require('express');
const controller = require('../controllers/analyticsController');
const { protect } = require('../middleware/authMiddleware');
const asyncHandler = require('../utils/asyncHandler');

const router = express.Router();

router.get('/', asyncHandler(protect), asyncHandler(controller.get));
router.post('/sync', asyncHandler(protect), asyncHandler(controller.sync));

module.exports = router;
