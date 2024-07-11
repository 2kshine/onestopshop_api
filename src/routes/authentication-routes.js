const authenticationController = require('../controllers/authentication-controller');
const express = require('express');
const router = express.Router();
router.post('/register', authenticationController.authenticate);

module.exports = router;
