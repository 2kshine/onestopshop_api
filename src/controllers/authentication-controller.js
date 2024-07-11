const logger = require('../../config/cloudwatch-logs');
const database = require('../services/database');
const jwtToken = require('../services/jsonwebtoken');
const { isEmailValid, isUsernameValid } = require('../services/property-validation');
const authenticate = async (req, res) => {
  let { username, email_address } = req.body;
  username = username.trim();
  email_address = email_address.trim();
  logger.log('authentication', 'Handling new USER!!!! Begin authentication process', req, 'info', { payload: { username, email_address } });
  try {
  // Check if email exist
    const isEmailExist = await database.findAUser({ email_address });

    if (isEmailExist) {
      logger.log('authentication', 'Email address found!!!! Aborting auth now. !!!', req, 'error', { error: { username, email_address } });
      return res.status(400).json({
        code: 'EMAIL_FOUND',
        message: 'Email is already registered. Are you trying to sign in?.'
      });
    }

    // Check if email format is valid
    if (!isEmailValid(email_address)) {
      logger.log('authentication', 'Email verification check Failed!!!! bad formatting. !!!', req, 'error', { error: { username, email_address } });
      return res.status(400).json({
        code: 'BAD_EMAIL_FORMAT',
        message: 'Email formatting is unacceptable. Please use correct email format.'
      });
    }

    // Check if username is unique
    const isUserNameUnique = await database.findAUser({ username });
    if (isUserNameUnique) {
      logger.log('authentication', 'Unique Username check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username, email_address } });
      return res.status(400).json({
        code: 'USERNAME_FOUND',
        message: 'Username has already been taken. Please use a different username.'
      });
    }

    // Check if username format is valid
    if (!isUsernameValid(username)) {
      logger.log('authentication', 'Unique Username format check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username, email_address } });
      return res.status(400).json({
        code: 'USERNAME_BAD_FORMAT',
        message: 'Username hformatting is bad. Please make sure there are no spaces involved.'
      });
    }

    // Begin to register user
    logger.log('authentication', 'Creating user in the database.. !!!', req, 'info', { payload: { username, email_address } });
    const newUser = await database.createAUser({ username, email_address });
    if (!newUser) {
      logger.log('authentication', 'Failed to create user.. !!! logging the error', req, 'error', { error: newUser });
    }
    logger.log('authentication', 'Successfully Created the user.. !!! logging the userid', req, 'error', { data: newUser.id });

    // Begin to verify user email address and send token via email
    logger.log('authentication', 'Begin the process of verifying user email address.. !!! Setting up jwt valid for 2 hours', req, 'info', { payload: { userId: newUser.id, email_address } });
    const verifyEmailToken = jwtToken({ userId: newUser.id, email_address }, '2h');
    console.log(verifyEmailToken);
  } catch (err) {
    console.log(err);
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    res.status(500).json({
      code: 'SERVER_ERROR',
      message: 'Internal server error. Please try again later!'
    });
  }
};

module.exports = { authenticate };
