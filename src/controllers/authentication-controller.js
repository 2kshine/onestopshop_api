const logger = require('../../config/cloudwatch-logs');
const database = require('../services/database');
const { sendJWTTokenForEmailVerification } = require('../services/email-service');
const jwtToken = require('../services/jsonwebtoken');
const { isEmailValid, isUsernameValid } = require('../services/property-validation');

const { UX_URL } = process.env;
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
      throw new Error('THROW_NEW_ERROR: Email is already registered. Are you trying to sign in?.');
    }

    // Check if email format is valid
    if (!isEmailValid(email_address)) {
      logger.log('authentication', 'Email verification check Failed!!!! bad formatting. !!!', req, 'error', { error: { username, email_address } });
      throw new Error('THROW_NEW_ERROR: Email formatting is unacceptable. Please use correct email format.');
    }

    // Check if username is unique
    const isUserNameUnique = await database.findAUser({ username });
    if (isUserNameUnique) {
      logger.log('authentication', 'Unique Username check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username, email_address } });
      throw new Error('THROW_NEW_ERROR: Username has already been taken. Please use a different username.');
    }

    // Check if username format is valid
    if (!isUsernameValid(username)) {
      logger.log('authentication', 'Unique Username format check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username, email_address } });
      throw new Error('THROW_NEW_ERROR: Username formatting is bad. Please make sure there are no spaces involved.');
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
    const verifyEmailToken = jwtToken({ userId: newUser.id, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });
    logger.log('authentication', 'Attempting to send verification token via email.. !!! ', req, 'info', { payload: { userId: newUser.id, email_address } });
    const { error, response } = await sendJWTTokenForEmailVerification(username, email_address, verifyEmailToken);
    if (error) {
      logger.log('authentication', 'Failed to send email .. !!! Check logs for details.', req, 'error', { userId: newUser.id, email_address, error });
      // No failover has been setup. Have a feature setup in UI to resend email feature.
    } else {
      logger.log('authentication', 'Email Sent Successfully.. !!!', req, 'info', { userId: newUser.id, email_address, data: response });
    }

    // Send response back marking end of user registration phase 1.
    return res.status(201).json({
      code: 'USER_REGISTER_SUCCESS',
      message: 'User Registered successfully.'
    });
  } catch (err) {
    console.log(err);
    let status = 500;
    let message = 'Internal server error. Please try again later!';
    if (err.message.includes('THROW_NEW_ERROR')) {
      status = 400;
      message = 'Something went wrong! Please try again later';
    } else {
      logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    }
    res.status(status).json({
      message
    });
  }
};

const verifyEmailAddressToken = async (req, res) => {
  // Condition of token verification
  /*
      Token on decode, ip or userAgent should match
      If neither one of those match then, it has been tampered with.
    */
  try {
    const { token } = req.query;
    const { JWT_SECRET_KEY } = process.env;
    logger.log('authentication', 'Email address token verification request.. !!! Commencing the request!!', req, 'info', { payload: token });

    // Check if token is present or not.
    if (!token) {
      logger.log('authentication', 'No token found.. !!! Aborting the request!!', req, 'error', null);
      throw new Error('THROW_NEW_ERROR: Failed to verify token.');
    }

    // Decode authenticity of the received token from query
    const userData = jwtToken.verify(token, JWT_SECRET_KEY);
    if (!userData) {
      logger.log('authentication', 'Failed to verify JWT TOKEN. !!! Aborting the request!!', req, 'error', { error: token });
      throw new Error('THROW_NEW_ERROR: Failed to verify token.');
    }

    // Verify Authenticity of the decoded token
    const { ip, userAgent, id, email_address } = userData;
    const user = await database.findAUser({ userId: id });
    if ((req.id !== ip && userAgent !== req.get('user-agent')) || !user) {
      logger.log('authentication', 'Failed authenticity of JWT TOKEN. Tampering detected !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, id, email_address } });
      throw new Error('THROW_NEW_ERROR: Failed to verify token.');
    }

    // Update the email verification record
    await database.updateAUser(user, { is_email_verified: true });
    logger.log('authentication', 'Successfully updated verified email data in the database !!! Creating token for password page now.!!!', req, 'info', { data: { ip, userAgent, id, email_address } });

    // Create JWT token to redirect to password change page.
    const verifyPasswordToken = jwtToken({ userId: user.id, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });

    // Send response back marking end of user registration phase 2.
    logger.log('authentication', 'Successfully created token for password page !!! Redirecting to the password page now.!!!', req, 'info', { payload: verifyPasswordToken });
    const redirectLink = UX_URL + '/create-password' + `?sessionToken=${verifyPasswordToken}`;
    return res.status(201).redirect(redirectLink);
  } catch (err) {
    console.log(err);
    let status = 500;
    let message = 'Internal server error. Please try again later!';
    if (err.message.includes('THROW_NEW_ERROR')) {
      status = 400;
      message = 'Something went wrong! Please try again later';
    } else {
      logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    }
    res.status(status).json({
      code: 'USER_VERIFY_UNSUCCESSFULL',
      message
    });
  }
};

const createPassword = async (req, res) => {

};

module.exports = { authenticate, verifyEmailAddressToken, createPassword };
