const jwt = require('jsonwebtoken');

const jwtToken = (user, expiry, reqMeta) => {
  const payload = {
    id: user.userId,
    email_address: user.email_address,
    ip: reqMeta.ip,
    userAgent: reqMeta.userAgent
  };
  return jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: expiry });
};

const jwtTokenAccessPasswordPage = (expiry) => {
  const payload = {
    access_password_page: true
  };
  return jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: expiry });
};

module.exports = { jwtToken, jwtTokenAccessPasswordPage };
