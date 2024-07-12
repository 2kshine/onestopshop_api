const authenticationController = require('../controllers/authentication-controller');
const express = require('express');
const router = express.Router();
router.post('/register', authenticationController.authenticate);
router.post('/verify-emailaddress', authenticationController.verifyEmailAddressToken);
router.post('/create-password', authenticationController.createPassword);

module.exports = router;
