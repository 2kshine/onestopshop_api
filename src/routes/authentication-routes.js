const authenticationController = require('../controllers/authentication-controller');
const { isAuthenticated } = require('../middleware/isAuthenticated');
const express = require('express');
const router = express.Router();
router.post('/register', authenticationController.register);
router.post('/verify-emailaddress', authenticationController.verifyEmailAddressToken);
router.post('/set-password', isAuthenticated, authenticationController.setPassword);
router.post('/login', authenticationController.login);
router.post('/logout', isAuthenticated, authenticationController.logout);
router.post('/change-password-code', isAuthenticated, authenticationController.changePasswordSendEmail);
router.post('/change-password', isAuthenticated, authenticationController.changePasswordAction);
router.post('/check-validity', authenticationController.isEmailAddressOrUsernameUnique);
router.post('/resend-email-check', authenticationController.resendEmailVerificationLink);
router.post('/check-password-token-validity', isAuthenticated, authenticationController.checkPasswordTokenValidity);

module.exports = router;
