const logger = require('../../config/cloudwatch-logs');

const CatchAndSendErrorResponse = (req, res, err, code = null) => {
  console.log(err);
  let status = 500;
  let message = 'Internal server error. Please try again later!';
  if (err.message.includes('THROW_NEW_ERROR')) {
    status = SpecificStatusSwitch(code);
    message = 'Something went wrong! Please try again later';
  } else {
    logger.log('authentication', 'Server error occured.. !!! Aborting the request!!', req, 'error', { error: err.message });
  }
  const toSendJsonResponse = { message };
  if (code) { toSendJsonResponse.code = code; }
  if (status === 401) { res.clearCookie('user_activity'); }
  return res.status(status).json(toSendJsonResponse);
};

const SpecificStatusSwitch = async (code) => {
  switch (code) {
    case 'ACCESS_DENIED':
      return 401;
    default:
      return 400;
  }
};
module.exports = { CatchAndSendErrorResponse };
