const authenticationController = require('../controllers/authentication-controller');
const { isAuthenticated } = require('../middleware/isAuthenticated');
const express = require('express');
const router = express.Router();

// login routes
router.post('/login', authenticationController.login);

// logout routes
router.post('/logout', isAuthenticated, authenticationController.logout);

// register routes
router.post('/register', authenticationController.register);

// verify email routes
router.post('/verify-emailaddress', authenticationController.verifyEmailAddressToken);
router.post('/resend-email-check', authenticationController.resendEmailVerificationLink);

// password routes
router.post('/set-password', isAuthenticated, authenticationController.setPassword);
router.post('/change-password-code', authenticationController.changePasswordSendEmail);
router.post('/change-password', authenticationController.changePasswordAction);
router.post('/check-password-token-validity', isAuthenticated, authenticationController.checkPasswordTokenValidity);

// schema check route
router.post('/check-validity', authenticationController.isEmailAddressOrUsernameUnique);

module.exports = router;
