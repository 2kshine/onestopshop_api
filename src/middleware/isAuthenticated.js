const jwt = require('jsonwebtoken');
const jwtToken = require('../services/jsonwebtoken');
const logger = require('../../config/cloudwatch-logs');

/*
      User agent value from user activity is a backup and also should be checked for user activity authenticity
    */
const { APP_AUTHORIZATION_NAME } = process.env;
const isAuthenticated = async (req, res, next) => {
  const user_agent = req.get('user-agent');
  const isSessionUserActive = req.signedCookies.user_activity;
  const { JWT_SECRET_KEY } = process.env;
  logger.log('authentication', 'Handling private request!!!! run authentication middleware', req, 'info', { payload: { ip: req.ip, user_agent, privateRoute: req.url } });

  try {
    // Check if token is present or not.
    const authHeader = req.headers[APP_AUTHORIZATION_NAME];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.log('authentication', 'No token found.. !!! Aborting the request!!', req, 'error', { error: { ip: req.ip, user_agent, privateRoute: req.url } });
      return res.status(401).json({ message: 'Token expired or not found' });
    }

    // Decode authenticity of the received token from query
    // parse auth header
    const token = authHeader.split(' ')[1];
    const userData = jwt.verify(token, JWT_SECRET_KEY);
    if (!userData) {
      logger.log('authentication', 'Failed to verify JWT TOKEN. !!! Aborting the request!!', req, 'error', { error: { ip: req.ip, user_agent, privateRoute: req.url } });
      return res.status(401).json({ message: 'Token expired or not found' });
    }

    // Verify Authenticity of the decoded token and user Activity
    const { ip, userAgent, id, email_address } = userData;
    if (userAgent !== user_agent) {
      logger.log('authentication', 'Failed authenticity of JWT TOKEN. Tampering detected !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, id, email_address, privateRoute: req.url } });
      return res.status(401).json({ message: 'Token expired or not found' });
    }

    // Check if user activity session expired and user agent matches
    if (!isSessionUserActive || (userAgent !== isSessionUserActive)) {
      logger.log('authentication', 'User session expired !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, sessionUserAgent: isSessionUserActive, id, email_address, privateRoute: req.url } });
      return res.status(401).json({ message: 'User session expired or not found' });
    }

    // Add userData to the req under user object
    req.user = userData;

    // Check if the jwt is about to expiry
    if ((userData.exp - Math.floor(Date.now() / 1000)) < 300) { // if expiry time is less than 5 minutes
      logger.log('authentication', 'Token is about to expire !!! Rotating token in process!!', req, 'warn', { payload: { ip, userAgent, id, email_address, privateRoute: req.url } });
      const token = jwtToken({ userId: id, email_address }, '2h', { ip: req.ip, userAgent: user_agent });
      res.setHeader(APP_AUTHORIZATION_NAME, token); // in UI check if the token header is present and if it is, then automatically update the session.
    }

    // Reset the user activity
    logger.log('authentication', 'Refreshing user activity !!!', req, 'info', { payload: { ip, userAgent, id, email_address, privateRoute: req.url } });
    res.cookie('user_activity', req.get('user-agent'), {
      path: '/',
      maxAge: 5 * 60 * 60 * 1000, // 10 minutes of activity
      signed: true
    });

    // Check if the password token is valid
    if (req.url === '/check-password-token-validity') {
      logger.log('authentication', 'Attempt to check if the passowrd page token is valid !!!', req, 'info', { payload: { ip, userAgent, id, email_address, privateRoute: req.url } });
      const isPasswordPageValid = jwt.verify(req.body.token, JWT_SECRET_KEY);
      if (!isPasswordPageValid || !isPasswordPageValid.access_password_page) {
        return res.status(404).json({ message: 'Not found' });
      }
    }
    next();
  } catch (err) {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
    return res.status(500);
  }
};

module.exports = { isAuthenticated };

// in frontend axios listen for token in headers and if token is present, then update that againts the old token
