const logger = require('../../config/cloudwatch-logs');
const database = require('../services/database');
const { sendJWTTokenForEmailVerification, sendSixDigitCodeByEmail } = require('../services/email-service');
const jwtToken = require('../services/jsonwebtoken');
const { isEmailValid, isUsernameValid, isPasswordStrong } = require('../services/property-validation');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { getRandomSixDigitInteger } = require('../helpers/misc');
const { sixDigitCodeRedis } = require('../services/redis-connect');

const { UX_URL, APP_AUTHORIZATION_NAME } = process.env;
const BCRYPT_SALT = 10;

const register = async (req, res) => {
  let { username, email_address } = req.body;
  username = username.trim();
  email_address = email_address.trim();
  logger.log('authentication', 'register: Handling new USER!!!! Begin authentication process', req, 'info', { payload: { username, email_address } });
  try {
    // Check if email format is valid
    if (!isEmailValid(email_address)) {
      logger.log('authentication', 'register: Email verification check Failed!!!! bad formatting. !!!', req, 'error', { error: { username, email_address } });
      return res.status(400);
    }

    // Check if email exist
    const isEmailExist = await database.findAUser({ email_address });
    if (isEmailExist) {
      logger.log('authentication', 'register: Email address found!!!! Aborting auth now. !!!', req, 'error', { error: { username, email_address } });
      return res.status(400);
    }

    // Check if username format is valid
    if (!isUsernameValid(username)) {
      logger.log('authentication', 'register: Unique Username format check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username, email_address } });
      return res.status(400);
    }

    // Check if username is unique
    const isUserNameUnique = await database.findAUser({ username });
    if (isUserNameUnique) {
      logger.log('authentication', 'register: Unique Username check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username, email_address } });
      return res.status(400);
    }

    // Begin to register user
    logger.log('authentication', 'register: Creating user in the database.. !!!', req, 'info', { payload: { username, email_address } });
    const newUser = await database.createAUser({ username, email_address });
    if (!newUser) {
      logger.log('authentication', 'register: Failed to create user.. !!! logging the error', req, 'error', { error: newUser });
    }
    logger.log('authentication', 'Successfully Created the user.. !!! logging the userid', req, 'error', { data: newUser.id });

    // Begin to verify user email address and send token via email
    logger.log('authentication', 'register: Begin the process of verifying user email address.. !!! Setting up jwt valid for 2 hours', req, 'info', { payload: { userId: newUser.id, email_address } });
    const verifyEmailToken = jwtToken({ userId: newUser.id, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });
    logger.log('authentication', 'register: Attempting to send verification token via email.. !!! ', req, 'info', { payload: { userId: newUser.id, email_address } });
    const { error, response } = await sendJWTTokenForEmailVerification(username, email_address, verifyEmailToken);
    if (error) {
      logger.log('authentication', 'register: Failed to send email .. !!! Check logs for details.', req, 'error', { userId: newUser.id, email_address, error });
      // No failover has been setup. Have a feature setup in UI to resend email feature.
      return res.status(500);
    } else {
      logger.log('authentication', 'register: Email Sent Successfully.. !!!', req, 'info', { userId: newUser.id, email_address, data: response });
    }

    // Send response back marking end of user registration phase 1.
    return res.status(201).json({
      code: 'USER_REGISTER_SUCCESS'
    });
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500);
  }
};

// Condition of token verification
/*
      Token on decode, ip or userAgent should match
      If neither one of those match then, it has been tampered with.
    */

const verifyEmailAddressToken = async (req, res) => {
  const { token } = req.query;
  const { JWT_SECRET_KEY } = process.env;
  logger.log('authentication', 'verifyEmailAddressToken: Email address token verification request.. !!! Commencing the request!!', req, 'info', { payload: token });

  try {
    // Check if token is present or not.
    if (!token) {
      logger.log('authentication', 'verifyEmailAddressToken: No token found.. !!! Aborting the request!!', req, 'error', null);
      return res.status(400);
    }

    // Decode authenticity of the received token from query
    const userData = jwt.verify(token, JWT_SECRET_KEY);
    if (!userData) {
      logger.log('authentication', 'verifyEmailAddressToken: Failed to verify JWT TOKEN. !!! Aborting the request!!', req, 'error', { error: token });
      return res.status(401);
    }

    // Verify Authenticity of the decoded token
    const { ip, userAgent, id, email_address } = userData;
    const user = await database.findAUser({ userId: id });
    if ((req.id !== ip && userAgent !== req.get('user-agent')) || !user) { // Can access token from any browser as long as ip matches
      logger.log('authentication', 'verifyEmailAddressToken: Failed authenticity of JWT TOKEN. Tampering detected !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, id, email_address } });
      return res.status(401);
    }

    // Update the email verification record
    await database.updateAUser(user, { is_email_verified: true });
    logger.log('authentication', 'verifyEmailAddressToken: Successfully updated verified email data in the database !!! Creating token for password page now.!!!', req, 'info', { data: { ip, userAgent, id, email_address } });

    // Create JWT token to redirect to password change page.
    const verifyPasswordToken = jwtToken({ userId: user.id, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });

    // Send response back marking end of user registration phase 2.
    logger.log('authentication', 'verifyEmailAddressToken: Successfully created token for password page !!! Redirecting to the password page now.!!!', req, 'info', null);
    const redirectLink = UX_URL + '/create-password';
    return res.status(201).setHeader(APP_AUTHORIZATION_NAME, verifyPasswordToken).cookie('user_activity', req.get('user-agent'), {
      maxAge: 10 * 60 * 1000, // 10 minutes of activity
      signed: true
    }).redirect(redirectLink);
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500);
  }
};

// Condition of password strength
/*
  Lowercase, uppercase, number, symbol and minimum length of 10
*/
const createPassword = async (req, res) => {
  const { password } = req.body;
  const { ip, userAgent, id, email_address } = req.user;
  logger.log('authentication', 'createPassword: Password change token verification request.. !!! Commencing the request!!', req, 'info', { payload: { ip, userAgent, id, email_address } });

  try {
    // Check if password passes the required verification
    logger.log('authentication', 'createPassword: Verifying password strength.. !!!', req, 'info', { payload: { ip, userAgent, id, email_address } });
    const isPassword = isPasswordStrong(password);
    if (!isPassword) {
      logger.log('authentication', 'Failed strength test of the password. !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, id, email_address } });
      return res.status(400);
    }

    // Encrypt password and store in the db.
    logger.log('authentication', 'createPassword: Attempt to encrypt password for storage!!!', req, 'info', { data: { ip, userAgent, id, email_address } });
    const hashPassword = await new Promise((resolve, reject) => {
      bcrypt.hash(password, BCRYPT_SALT, (err, hash) => {
        if (err) {
          logger.log('authentication', 'createPassword: Failed to encrypt password. !!! Check logs!!', req, 'error', { error: { ip, userAgent, id, email_address, err } });
          return res.status(500);
        }
        resolve(hash);
      });
    });
    await database.updateAUser(await database.findAUser({ userId: id, email_address }), { password: hashPassword });
    logger.log('authentication', 'createPassword: Successfully stored encrypted password. !!! Redirecting!!', req, 'info', { data: { ip, userAgent, id, email_address } });

    // Redirect user to the portal marking end of user registration phase 3.
    const redirectLink = UX_URL + '/dashboard';
    return res.redirect(redirectLink);
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500);
  }
};

// Condition of login
/*
  To login user can either put in username or email and password
  User session will be valid for 10 minutes if no action is detected then user have to login again.
*/
const login = async (req, res) => {
  const { loginUser, password } = req.body;
  logger.log('authentication', 'login: Login request received.. !!! Commencing the request!!', req, 'info', { payload: loginUser });

  try {
    // Check if loginUser is email or not and also if user exist
    const isEmail = isEmailValid(loginUser);
    const loginPayload = {};
    loginPayload[!isEmail ? 'username' : 'email_address'] = loginUser;
    const user = await database.findAUser(loginPayload);
    if (!user) {
      logger.log('authentication', 'login: Failed to find account with user login. !!! Check logs!!', req, 'error', { error: { loginUser } });
      return res.status(400);
    }

    // Check if password match
    const { username, email_address, hashPassword, userId } = user;
    logger.log('authentication', 'login: Account found. Now checking if password match.. !!! Commencing the password check!!', req, 'info', { payload: { username, email_address } });
    await new Promise((resolve, reject) => {
      bcrypt.compare(password, hashPassword, (err, result) => {
        if (err) {
          logger.log('authentication', 'login: Failed to check password. !!! Check logs!!', req, 'error', { error: { username, email_address, err } });
          return res.status(500);
        }
        if (!result) {
          logger.log('authentication', 'login: Password is incorrect. !!! Aborting the request!!', req, 'error', { error: { username, email_address, err } });
          return res.status(401);
        }
        logger.log('authentication', 'login: Successfully stored encrypted password. !!! Setup user activity session!! Redirecting!!', req, 'info', { data: { username, email_address } });
        resolve(result);
      });
    });

    // Password matches Generate a token and redirect user to the portal with user session and token
    const loginSessionToken = jwtToken({ userId, email_address }, '2h', { ip: req.ip, userAgent: req.get('user-agent') });
    const redirectLink = UX_URL + '/dashboard';
    return res.status(201).setHeader(APP_AUTHORIZATION_NAME, loginSessionToken).cookie('user_activity', req.get('user-agent'), {
      maxAge: 10 * 60 * 1000, // 10 minutes of activity
      signed: true
    }).redirect(redirectLink);
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500);
  }
};

const logout = async (req, res) => {
  const { ip, userAgent, id, email_address } = req.body;
  logger.log('authentication', 'logout: Logout request received.. !!! Commencing the request!! Clearing user_activity cookie', req, 'info', { payload: { ip, userAgent, id, email_address } });

  try {
    // Clear cookie and redirect to login page
    await res.clearCookie('user_activity');
    logger.log('authentication', 'logout: Logged out successfully.. !!! Redirecting to the home page.', req, 'info', { payload: { ip, userAgent, id, email_address } });
    const redirectLink = UX_URL + '/';
    res.status(200).redirect(redirectLink);
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500);
  }
};

const changePasswordSendEmail = async (req, res) => {
  const { ip, userAgent, id, email_address } = req.user;
  logger.log('authentication', 'changePasswordSendEmail: Password change request found.. !!! Commencing the request!!', req, 'info', { payload: { ip, userAgent, id, email_address } });
  try {
    // Send six digit code and store in redis session
    logger.log('authentication', 'changePasswordSendEmail: Attempt to get six digit code and store in redis session.. !!!', req, 'info', { payload: { ip, userAgent, id, email_address } });
    const sixDigitCode = getRandomSixDigitInteger();
    const setSessionResponse = await sixDigitCodeRedis(`${id}`, 'set', sixDigitCode.toString());
    if (setSessionResponse !== 'SUCCESS') {
      logger.log('authentication', 'changePasswordSendEmail: Failed to store session data .. !!! Check logs for details.', req, 'error', { ip, userAgent, id, email_address, error: setSessionResponse });
    }

    // Send Email with the six digit code
    const user = await database.findAUser({ id, email_address });
    logger.log('authentication', 'changePasswordSendEmail: Session stored successfully, Attempting to send email Email sent successfully.. !!! ', req, 'info', { payload: { ip, userAgent, id, email_address } });
    const { error, response } = await sendSixDigitCodeByEmail(user.username, email_address, sixDigitCode);
    if (error) {
      logger.log('authentication', 'changePasswordSendEmail: Failed to send email .. !!! Check logs for details.', req, 'error', { ip, userAgent, id, email_address, error });
      // No failover has been setup. Have a feature setup in UI to resend email feature.
      return res.status(500);
    } else {
      logger.log('authentication', 'changePasswordSendEmail: Email sent successfully.. !!! ', req, 'info', { payload: { ip, userAgent, id, email_address, data: response } });
    }

    return res.status(200).json({
      code: 'EMAIL_SENT'
    });
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500);
  }
};

const changePasswordAction = async (req, res) => {
  const { ip, userAgent, id, email_address } = req.user;
  const { six_digit_code, password } = req.body;
  logger.log('authentication', 'changePasswordAction: Password change Action request found.. !!! Commencing the request!!', req, 'info', { payload: { ip, userAgent, id, email_address } });
  try {
    // Get six digit code from redis
    logger.log('authentication', 'changePasswordAction: Attempt to get six digit from redis session.. !!!', req, 'info', { payload: { ip, userAgent, id, email_address } });
    const setSessionResponse = await sixDigitCodeRedis(`${id}`, 'get');
    if (!setSessionResponse) {
      logger.log('authentication', 'changePasswordAction: Failed to retrieve session data .. !!', req, 'error', { ip, userAgent, id, email_address });
      return res.status(400);
    }

    // Check if sixDigitCode from the user matches the one in the session, then delete once matched
    if (six_digit_code.toString() !== setSessionResponse) {
      logger.log('authentication', 'changePasswordAction: Code received from the user doesnt match the one in the session .. !!', req, 'error', { ip, userAgent, id, email_address, user_code: six_digit_code });
      return res.status(400);
    }
    await sixDigitCodeRedis(`${id}`, 'delete');

    // Check if the password satisfies the validation process.
    logger.log('authentication', 'changePasswordAction: Six digit code matches, verifying password strength.. !!!', req, 'info', { payload: { ip, userAgent, id, email_address } });
    const isPassword = isPasswordStrong(password);
    if (!isPassword) {
      logger.log('authentication', 'changePasswordAction: Failed strength test of the password. !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, id, email_address } });
      return res.status(401);
    }

    // Encrypt password and store in the db.
    logger.log('authentication', 'changePasswordAction: Attempt to encrypt password for storage!!!', req, 'info', { data: { ip, userAgent, id, email_address } });
    const hashPassword = await new Promise((resolve, reject) => {
      bcrypt.hash(password, BCRYPT_SALT, (err, hash) => {
        if (err) {
          logger.log('authentication', 'changePasswordAction: Failed to encrypt password. !!! Check logs!!', req, 'error', { error: { ip, userAgent, id, email_address, err } });
          return res.status(500);
        }
        resolve(hash);
      });
    });
    await database.updateAUser(await database.findAUser({ userId: id, email_address }), { password: hashPassword });
    logger.log('authentication', 'changePasswordAction: Successfully stored encrypted password. Sending Response!!', req, 'info', { data: { ip, userAgent, id, email_address } });

    return res.status(200).json({
      code: 'PASSWORD_CHANGED_SUCCESS'
    });
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500);
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
        return res.status(400);
      }

      // Check if email exist
      const isEmailExist = await database.findAUser({ email_address });
      if (isEmailExist) {
        logger.log('authentication', 'isEmailAddressOrUsernameUnique: Email address found!!!! Aborting auth now. !!!', req, 'error', { error: { email_address } });
        return res.status(400);
      }
    } else {
    // Check if username format is valid
      if (!isUsernameValid(username)) {
        logger.log('authentication', 'isEmailAddressOrUsernameUnique: Unique Username format check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username } });
        return res.status(400);
      }

      // Check if username is unique
      const isUserNameUnique = await database.findAUser({ username });
      if (isUserNameUnique) {
        logger.log('authentication', 'isEmailAddressOrUsernameUnique: Unique Username check Failed!!!! Aborting authentication process.. !!!', req, 'error', { error: { username } });
        return res.status(400);
      }
    }

    logger.log('authentication', 'isEmailAddressOrUsernameUnique: Unique Username check Success!!!! Returning request.. !!!', req, 'info', { error: { username, email_address } });
    // Return with a success code
    return res.status(200).json({
      code: 'EMAIL_OR_USER_UNIQUE'
    });
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500);
  }
};

module.exports = { register, verifyEmailAddressToken, createPassword, login, logout, changePasswordSendEmail, changePasswordAction, isEmailAddressOrUsernameUnique };
