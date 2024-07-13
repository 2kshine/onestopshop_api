const authenticationController = require('../controllers/authentication-controller');
const { isAuthenticated } = require('../middleware/isAuthenticated');
const express = require('express');
const router = express.Router();
router.post('/register', authenticationController.register);
router.post('/verify-emailaddress', authenticationController.verifyEmailAddressToken);
router.post('/create-password', isAuthenticated, authenticationController.createPassword);
router.post('/login', authenticationController.login);
router.post('/logout', isAuthenticated, authenticationController.logout);

module.exports = router;
