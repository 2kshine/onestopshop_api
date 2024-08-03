const logger = require('../../config/cloudwatch-logs');
const database = require('../services/database');
const { sendJWTTokenForEmailVerification, sendSixDigitCodeByEmail } = require('../services/email-service');
const { jwtToken, jwtTokenAccessPasswordPage } = require('../services/jsonwebtoken');
const { isEmailValid, isUsernameValid, isPasswordStrong } = require('../services/property-validation');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getRandomSixDigitInteger } = require('../helpers/misc');
const { sixDigitCodeRedis } = require('../services/redis-connect');

const { APP_AUTHORIZATION_NAME } = process.env;
const BCRYPT_SALT = 10;

const register = async (req, res) => {
  let { username, email_address } = req.body;
  username = username.trim();
  email_address = email_address.trim();
  logger.log('authentication', 'register: Handling new USER!!!! Begin authentication process', req, 'info', { payload: { username, email_address } });
  try {
    // check if email address is present then verify that
    // Check if email format is valid
    if (!isEmailValid(email_address)) {
      logger.log('authentication', 'register: Email verification check Failed!!!! bad formatting. !!!', req, 'error', { error: { email_address } });
      return res.status(400).json({ message: 'Email is invalid' });
    }

    // Check if email exist
    const isEmailExist = await database.findAUser({ email_address });
    if (isEmailExist) {
      logger.log('authentication', 'register: Email address found!!!! Aborting auth now. !!!', req, 'error', { error: { email_address } });
      return res.status(400).json({ message: 'Email is already taken' });
    }

    // Check if username format is valid
    if (!isUsernameValid(username)) {
      logger.log('authentication', 'register: Unique Username format check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username } });
      return res.status(400).json({ message: 'Username is invalid' });
    }

    // Check if username is unique
    const isUserNameUnique = await database.findAUser({ username });
    if (isUserNameUnique) {
      logger.log('authentication', 'register: Unique Username check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username } });
      return res.status(400).json({ message: 'Username is already taken' });
    }

    // Begin to register user
    logger.log('authentication', 'register: Creating user in the database.. !!!', req, 'info', { payload: { username, email_address } });
    const newUser = await database.createAUser({ username, email_address });
    if (!newUser) {
      logger.log('authentication', 'register: Failed to create user.. !!! logging the error', req, 'error', { error: newUser });
      return res.status(500).json({ message: 'Something went wrong' });
    }
    logger.log('authentication', 'Successfully Created the user.. !!! logging the userid', req, 'error', { data: newUser.userId });

    // Begin to verify user email address and send token via email
    logger.log('authentication', 'register: Begin the process of verifying user email address.. !!! Setting up jwt valid for 2 hours', req, 'info', { payload: { userId: newUser.userId, email_address } });
    const verifyEmailToken = jwtToken({ userId: newUser.userId, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });
    logger.log('authentication', 'register: Attempting to send verification token via email.. !!! ', req, 'info', { payload: { userId: newUser.userId, email_address } });
    const { error, response } = await sendJWTTokenForEmailVerification(username, email_address, verifyEmailToken);
    if (error) {
      logger.log('authentication', 'register: Failed to send email .. !!! Check logs for details.', req, 'error', { userId: newUser.userId, email_address, error });
      // No failover has been setup. Have a feature setup in UI to resend email feature.
      return res.status(500).json({ message: 'Something went wrong.' });
    } else {
      logger.log('authentication', 'register: Email Sent Successfully.. !!!', req, 'info', { userId: newUser.userId, email_address, data: response });
    }

    // Send response back marking end of user registration phase 1.
    return res.status(201).json({
      code: 'USER_REGISTER_SUCCESS'
    });
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' }); ;
  }
};

// Condition of token verification
/*
      Token on decode, ip or userAgent should match
      If neither one of those match then, it has been tampered with.
    */

const verifyEmailAddressToken = async (req, res) => {
  const { token } = req.body;
  const { JWT_SECRET_KEY } = process.env;
  // logger.log('authentication', 'verifyEmailAddressToken: Email address token verification request.. !!! Commencing the request!!', req, 'info', { payload: token });

  try {
    // Check if token is present or not.
    if (!token) {
      logger.log('authentication', 'verifyEmailAddressToken: No token found.. !!! Aborting the request!!', req, 'error', null);
      return res.status(400).json({ message: 'No token found' });
    }

    // Decode authenticity of the received token from query
    const userData = jwt.verify(token, JWT_SECRET_KEY);
    if (!userData) {
      logger.log('authentication', 'verifyEmailAddressToken: Failed to verify JWT TOKEN. !!! Aborting the request!!', req, 'error', { error: token });
      return res.status(401).json({ message: 'Forbidden link' });
    }

    // Verify Authenticity of the decoded token
    const { ip, userAgent, id, email_address } = userData;
    const user = await database.findAUser({ userId: id });
    if (!user) { // Can access token from any browser as long as ip matches
      logger.log('authentication', 'verifyEmailAddressToken: Failed authenticity of JWT TOKEN. Tampering detected !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, id, email_address } });
      return res.status(401).json({ message: 'Forbidden link' });
    }

    // Check if the token has been verified, if it has return 400 error
    if (user.is_email_verified) {
      logger.log('authentication', 'verifyEmailAddressToken: Email has already been verified!!! Aborting the request!!', req, 'error', { error: { ip, userAgent, id, email_address } });
      return res.status(410).json({ message: 'Token expired' });
    }

    // Update the email verification record
    await database.updateAUser(user, { is_email_verified: true });
    logger.log('authentication', 'verifyEmailAddressToken: Successfully updated verified email data in the database !!! Creating token for password page now.!!!', req, 'info', { data: { ip, userAgent, id, email_address } });

    // Create JWT token to redirect to password change page and another token to access password page.
    const headerToken = jwtToken({ userId: user.userId, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });
    const verifyPasswordToken = jwtTokenAccessPasswordPage('1h');

    // Send response back marking end of user registration phase 2.
    logger.log('authentication', 'verifyEmailAddressToken: Successfully created token for password page !!! Redirecting to the password page now.!!!', req, 'info', null);

    // Set Headers
    res.setHeader(APP_AUTHORIZATION_NAME, headerToken);

    // return the cookie
    res.cookie('user_activity', req.get('user-agent'), {
      path: '/',
      maxAge: 5 * 60 * 60 * 1000, // 10 minutes of activity
      signed: true
    });
    return res.status(200).json({ token: verifyPasswordToken });
  } catch (err) {
    console.log(err);
    logger.log('authentication', 'verifyEmailAddressToken: Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' }); ;
  }
};

// Condition of password strength
/*
  Lowercase, uppercase, number, symbol and minimum length of 10
*/
const setPassword = async (req, res) => {
  const { password, confirmation_password } = req.body;
  const { ip, userAgent, id, email_address } = req.user;
  logger.log('authentication', 'setPassword: Password change token verification request.. !!! Commencing the request!!', req, 'info', { payload: { ip, userAgent, id, email_address } });

  try {
    // Check if password passes the required verification
    logger.log('authentication', 'setPassword: Verifying password strength.. !!!', req, 'info', { payload: { ip, userAgent, id, email_address } });
    const isPassword = isPasswordStrong(password);
    if (!isPassword) {
      logger.log('authentication', 'setPassword: Failed strength test of the password. !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, id, email_address } });
      return res.status(400).json({ message: 'Failed password strength' });
    }

    // Check if the password and confirm password are the same.
    logger.log('authentication', 'setPassword: Checking if password matches.... !!!', req, 'info', { payload: { ip, userAgent, id, email_address } });
    if (password !== confirmation_password) {
      logger.log('authentication', 'setPassword: Passwords does not match... !!!', req, 'error', { payload: { ip, userAgent, id, email_address } });
      return res.status(400).json({ message: 'Password mismatched' });
    }

    // Encrypt password and store in the db.
    logger.log('authentication', 'setPassword: Attempt to encrypt password for storage!!!', req, 'info', { data: { ip, userAgent, id, email_address } });
    const hashPassword = await new Promise((resolve, reject) => {
      bcrypt.hash(password, BCRYPT_SALT, (err, hash) => {
        if (err) {
          logger.log('authentication', 'setPassword: Failed to encrypt password. !!! Check logs!!', req, 'error', { error: { ip, userAgent, id, email_address, err } });
          return res.status(500).json({ message: 'Something went wrong!!' });
        }
        resolve(hash);
      });
    });
    await database.updateAUser(await database.findAUser({ userId: id, email_address }), { password: hashPassword });
    logger.log('authentication', 'setPassword: Successfully stored encrypted password. !!! Redirecting!!', req, 'info', { data: { ip, userAgent, id, email_address } });

    return res.status(201).json({});
  } catch (err) {
    logger.log('authentication', 'setPassword: Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' });
  }
};

// Condition of login
/*
  To login user can either put in username or email and password
  User session will be valid for 10 minutes if no action is detected then user have to login again.
*/
const login = async (req, res) => {
  const { login_user, password } = req.body;
  logger.log('authentication', 'login: Login request received.. !!! Commencing the request!!', req, 'info', { payload: login_user });

  try {
    // Check if loginUser is email or not and also if user exist
    const isEmail = isEmailValid(login_user);
    const loginPayload = {};
    loginPayload[!isEmail ? 'username' : 'email_address'] = login_user;
    const user = await database.findAUser(loginPayload);
    if (!user) {
      logger.log('authentication', 'login: Failed to find account with user login. !!! Check logs!!', req, 'error', { error: { login_user } });
      return res.status(400).json({ message: 'No user found' });
    }

    // Check if password match
    const { username, email_address, password: hashPassword, userId } = user;
    logger.log('authentication', 'login: Account found. Now checking if password match.. !!! Commencing the password check!!', req, 'info', { payload: { username, email_address } });
    await new Promise((resolve, reject) => {
      bcrypt.compare(password, hashPassword, (err, result) => {
        if (err) {
          logger.log('authentication', 'login: Failed to check password. !!! Check logs!!', req, 'error', { error: { username, email_address, err } });
          return res.status(500).json({ message: 'Something went wrong!!' }); ;
        }
        if (!result) {
          logger.log('authentication', 'login: Password is incorrect. !!! Aborting the request!!', req, 'error', { error: { username, email_address, err } });
          return res.status(401).json({ message: 'Login failed' });
        }
        logger.log('authentication', 'login: Successfully stored encrypted password. !!! Setup user activity session!! Redirecting!!', req, 'info', { data: { username, email_address } });
        resolve(result);
      });
    });

    // Password matches Generate a token and redirect user to the portal with user session and token
    const loginSessionToken = jwtToken({ userId, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });
    return res.status(200).setHeader(APP_AUTHORIZATION_NAME, loginSessionToken).cookie('user_activity', req.get('user-agent'), {
      maxAge: 10 * 60 * 1000, // 10 minutes of activity
      signed: true
    }).json({ message: 'success' });
  } catch (err) {
    logger.log('authentication', 'login: Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' });
  }
};

const logout = async (req, res) => {
  const { ip, userAgent, id, email_address } = req.body;
  logger.log('authentication', 'logout: Logout request received.. !!! Commencing the request!! Clearing user_activity cookie', req, 'info', { payload: { ip, userAgent, id, email_address } });

  try {
    // Clear cookie and redirect to login page
    res.clearCookie('user_activity');
    logger.log('authentication', 'logout: Logged out successfully.. !!! Redirecting to the home page.', req, 'info', { payload: { ip, userAgent, id, email_address } });
    res.status(200).json({ message: 'success' });
  } catch (err) {
    logger.log('authentication', 'logout: Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' }); ;
  }
};

const changePasswordSendEmail = async (req, res) => {
  const { email_address } = req.body;
  logger.log('authentication', 'changePasswordSendEmail: Password change request found.. !!! Commencing the request!!', req, 'info', { email_address });
  try {
    // Find user with the email_address
    const user = await database.findAUser({ email_address });
    if (!user) {
      logger.log('authentication', 'changePasswordSendEmail: Failed to get user object with email address.. !!! Aborting!!', req, 'info', { email_address });
      return res.status(400).json({ message: 'Failed' });
    }

    // Send six digit code and store in redis session
    logger.log('authentication', 'changePasswordSendEmail: Attempt to get six digit code and store in redis session.. !!!', req, 'info', { email_address });
    const sixDigitCode = getRandomSixDigitInteger();
    const setSessionResponse = await sixDigitCodeRedis(`${user.userId}`, 'set', sixDigitCode.toString());
    if (setSessionResponse !== 'SUCCESS') {
      logger.log('authentication', 'changePasswordSendEmail: Failed to store session data .. !!! Check logs for details.', req, 'error', { email_address });
    }

    logger.log('authentication', 'changePasswordSendEmail: Session stored successfully, Attempting to send email Email sent successfully.. !!! ', req, 'info', { email_address });
    const { error, response } = await sendSixDigitCodeByEmail(user.username, email_address, sixDigitCode);
    if (error) {
      console.log(error);
      logger.log('authentication', 'changePasswordSendEmail: Failed to send email .. !!! Check logs for details.', req, 'error', { email_address });
      // No failover has been setup. Have a feature setup in UI to resend email feature.
      return res.status(500).json({ message: 'Something went wrong!!' }); ;
    } else {
      logger.log('authentication', 'changePasswordSendEmail: Email sent successfully.. !!! ', req, 'info', { email_address });
    }

    return res.status(200).json({
      code: 'EMAIL_SENT'
    });
  } catch (err) {
    console.log(err);
    logger.log('authentication', 'changePasswordSendEmail: Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' }); ;
  }
};

const changePasswordAction = async (req, res) => {
  const { email_address, six_digit_code } = req.body;
  logger.log('authentication', 'changePasswordAction: Password change Action request found.. !!! Commencing the request!!', req, 'info', { email_address, six_digit_code });
  try {
    // Get user account based on email address
    const user = await database.findAUser({ email_address });
    if (!user) {
      logger.log('authentication', 'changePasswordAction: Failed to get user object with email address.. !!! Aborting!!', req, 'info', { email_address, six_digit_code });
      return res.status(400).json({ message: 'Failed' });
    }

    // Get six digit code from redis
    logger.log('authentication', 'changePasswordAction: Attempt to get six digit from redis session.. !!!', req, 'info', { email_address, six_digit_code });
    const setSessionResponse = await sixDigitCodeRedis(`${user.userId}`, 'get');
    if (!setSessionResponse) {
      logger.log('authentication', 'changePasswordAction: Failed to retrieve session data .. !!', req, 'error', { email_address, six_digit_code });
      return res.status(400).json({ message: 'Failed' });
    }

    // Check if sixDigitCode from the user matches the one in the session, then delete once matched
    if (six_digit_code.toString() !== setSessionResponse) {
      logger.log('authentication', 'changePasswordAction: Code received from the user doesnt match the one in the session .. !!', req, 'error', { email_address, six_digit_code });
      return res.status(400).json({ message: 'Mismatch' });
    }
    await sixDigitCodeRedis(`${user.userId}`, 'delete');

    // Create JWT token to redirect to password change page and another token to access password page.
    const headerToken = jwtToken({ userId: user.userId, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });
    const verifyPasswordToken = jwtTokenAccessPasswordPage('1h');

    // Send response back marking end of user registration phase 2.
    logger.log('authentication', 'changePasswordAction: Successfully created token for password page !!! Redirecting to the password page now.!!!', req, 'info', null);

    // Set Headers
    res.setHeader(APP_AUTHORIZATION_NAME, headerToken);

    // return the cookie
    res.cookie('user_activity', req.get('user-agent'), {
      path: '/',
      maxAge: 5 * 60 * 60 * 1000, // 10 minutes of activity
      signed: true
    });
    return res.status(200).json({ token: verifyPasswordToken });
  } catch (err) {
    logger.log('authentication', 'changePasswordAction: Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' }); ;
  }
};

const isEmailAddressOrUsernameUnique = async (req, res) => {
  let { username, email_address } = req.body;
  username = username?.trim();
  email_address = email_address?.trim();
  logger.log('authentication', 'isEmailAddressOrUsernameUnique: Attempt to check if provided data is unique or not!!!! Begin checking process', req, 'info', { payload: { username, email_address } });
  try {
    // check if email address is present then verify that
    if (email_address) {
    // Check if email format is valid
      if (!isEmailValid(email_address)) {
        logger.log('authentication', 'isEmailAddressOrUsernameUnique: Email verification check Failed!!!! bad formatting. !!!', req, 'error', { error: { email_address } });
        return res.status(400).json({ message: 'Email is invalid' });
      }

      // Check if email exist
      const isEmailExist = await database.findAUser({ email_address });
      if (isEmailExist) {
        logger.log('authentication', 'isEmailAddressOrUsernameUnique: Email address found!!!! Aborting auth now. !!!', req, 'error', { error: { email_address } });
        return res.status(400).json({ message: 'Email is already taken' });
      }
    } else {
    // Check if username format is valid
      if (!isUsernameValid(username)) {
        logger.log('authentication', 'isEmailAddressOrUsernameUnique: Unique Username format check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username } });
        return res.status(400).json({ message: 'Username is invalid' });
      }

      // Check if username is unique
      const isUserNameUnique = await database.findAUser({ username });
      if (isUserNameUnique) {
        logger.log('authentication', 'isEmailAddressOrUsernameUnique: Unique Username check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username } });
        return res.status(400).json({ message: 'Username is already taken' });
      }
    }

    logger.log('authentication', 'isEmailAddressOrUsernameUnique: Unique Username check Success!!!! Returning request.. !!!', req, 'info', { error: { username, email_address } });
    // Return with a success code
    res.status(200).json({
      code: 'EMAIL_OR_USER_UNIQUE'
    });
  } catch (err) {
    logger.log('authentication', 'isEmailAddressOrUsernameUnique: Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' }); ;
  }
};

const resendEmailVerificationLink = async (req, res) => {
  let { username, email_address } = req.body;
  username = username?.trim();
  email_address = email_address?.trim();
  logger.log('authentication', 'resendEmailVerificationLink: Attempt to re send the email link!!!! Begin checking process', req, 'info', { payload: { username, email_address } });
  try {
    // Check if a record exist with the username and email_address
    const isUserExist = await database.findAUser({ email_address });
    if (!isUserExist) {
      logger.log('authentication', 'resendEmailVerificationLink: No record was found with that username and email address !!!', req, 'error', { error: { username, email_address } });
      return res.status(404).json({ message: 'No user record found.' });
    }

    // Check if the email has been verified or not.
    if (isUserExist.is_email_verified) {
      logger.log('authentication', 'resendEmailVerificationLink: Email has already been verified!!! Aborting request', req, 'error', { error: { username, email_address } });
      return res.status(200).json({ message: 'Email has been verified.' });
    }

    // Resend verification email link to verify user email address
    logger.log('authentication', 'resendEmailVerificationLink: Begin the process of verifying user email address.. !!! Setting up jwt valid for 2 hours', req, 'info', { payload: { userId: isUserExist.userId, email_address } });
    const verifyEmailToken = jwtToken({ userId: isUserExist.userId, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });
    logger.log('authentication', 'resendEmailVerificationLink: Attempting to send verification token via email.. !!! ', req, 'info', { payload: { userId: isUserExist.userId, email_address } });
    const { error, response } = await sendJWTTokenForEmailVerification(username, email_address, verifyEmailToken);
    if (error) {
      logger.log('authentication', 'resendEmailVerificationLink: Failed to send email .. !!! Check logs for details.', req, 'error', { userId: isUserExist.userId, email_address, error });
      // No failover has been setup. Have a feature setup in UI to resend email feature.
      return res.status(500).json({ message: 'Something went wrong.' });
    } else {
      logger.log('authentication', 'resendEmailVerificationLink: Resend email verification Success!!!! Returning request.. !!!', req, 'info', { userId: isUserExist.userId, email_address, data: response });
    }

    // Return with a success code
    res.status(202).json({ // Request is accepted.
      code: 'EMAIL_RESEND_SUCCESS'
    });
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' }); ;
  }
};

const checkPasswordTokenValidity = async (req, res) => {
  logger.log('authentication', 'checkPasswordTokenValidity: Password validity check passed!!!!', req, 'info');
  try {
    // Return with a success code
    res.status(200).json({
      code: 'CHECK_VALID'
    });
  } catch (err) {
    logger.log('authentication', 'checkPasswordTokenValidity: Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500).json({ message: 'Something went wrong!!' }); ;
  }
};
module.exports = { register, verifyEmailAddressToken, setPassword, login, logout, changePasswordSendEmail, changePasswordAction, isEmailAddressOrUsernameUnique, resendEmailVerificationLink, checkPasswordTokenValidity };
