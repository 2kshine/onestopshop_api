const jwt = require('jsonwebtoken');
const jwtToken = require('../services/jsonwebtoken');
const logger = require('../../config/cloudwatch-logs');
const { CatchAndSendErrorResponse } = require('../helpers/error-response');

/*
      User agent value from user activity is a backup and also should be checked for user activity authenticity
    */
const tokenName = 'X-ONESTOPSHOP-TOKEN';
const isAuthenticated = async (req, res, next) => {
  const user_agent = req.get('user-agent');
  const isSessionUserActive = req.signedCookies.user_activity;
  const { JWT_SECRET_KEY } = process.env;
  logger.log('authentication', 'Handling private request!!!! run authentication middleware', req, 'info', { payload: { ip: req.ip, user_agent, privateRoute: req.url } });

  try {
    // Check if token is present or not.
    const authHeader = req.headers[tokenName];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.log('authentication', 'No token found.. !!! Aborting the request!!', req, 'error', { error: { ip: req.ip, user_agent, privateRoute: req.url } });
      throw new Error('THROW_NEW_ERROR: No token found.. !!! Aborting the request!!');
    }

    // Decode authenticity of the received token from query
    // parse auth header
    const token = authHeader.split(' ')[1];
    const userData = jwt.verify(token, JWT_SECRET_KEY);
    if (!userData) {
      logger.log('authentication', 'Failed to verify JWT TOKEN. !!! Aborting the request!!', req, 'error', { error: { ip: req.ip, user_agent, privateRoute: req.url } });
      throw new Error('THROW_NEW_ERROR: Failed to verify JWT TOKEN. !!! Aborting the request!!');
    }

    // Verify Authenticity of the decoded token and user Activity
    const { ip, userAgent, id, email_address } = userData;
    if (userAgent !== user_agent) {
      logger.log('authentication', 'Failed authenticity of JWT TOKEN. Tampering detected !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, id, email_address, privateRoute: req.url } });
      throw new Error('THROW_NEW_ERROR:Failed authenticity of JWT TOKEN. Tampering detected !!!');
    }

    // Check if user activity session expired and user agent matches
    if (!isSessionUserActive || (userAgent !== isSessionUserActive)) {
      logger.log('authentication', 'User session expired !!! Aborting the request!!', req, 'error', { error: { ip, userAgent, sessionUserAgent: isSessionUserActive, id, email_address, privateRoute: req.url } });
      throw new Error('THROW_NEW_ERROR: User session expired !!! Aborting the request!!');
    }

    // Add userData to the req under user object
    req.user = userData;

    // Check if the jwt is about to expiry
    if ((userData.exp - Math.floor(Date.now() / 1000)) < 300) { // if expiry time is less than 5 minutes
      logger.log('authentication', 'Token is about to expire !!! Rotating token in process!!', req, 'warn', { payload: { ip, userAgent, id, email_address, privateRoute: req.url } });
      const token = jwtToken({ userId: id, email_address }, '2h', { ip: req.ip, userAgent: user_agent });
      res.setHeader(tokenName, token); // in UI check if the token header is present and if it is, then automatically update the session.
    }

    // Reset the user activity
    logger.log('authentication', 'Refreshing user activity !!!', req, 'info', { payload: { ip, userAgent, id, email_address, privateRoute: req.url } });
    res.cookie('user_activity', 'user_activity', {
      maxAge: 10 * 60 * 1000, // 10 minutes of activity
      signed: true
    });
    next();
  } catch (err) {
    CatchAndSendErrorResponse({ headers: req.headers }, res, err, 'ACCESS_DENIED');
  }
};

module.exports = { isAuthenticated };

// in frontend axios listen for token in headers and if token is present, then update that againts the old token
