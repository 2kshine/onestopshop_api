const jwt = require('jsonwebtoken');

const jwtToken = (user, expiry) => {
  const payload = {
    id: user.userId,
    email_address: user.email_address
  };
  return jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: expiry });
};

module.exports = jwtToken;
