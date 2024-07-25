const { passwordStrength } = require('check-password-strength');

const isEmailValid = (emailAddress) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(emailAddress);
};

const isUsernameValid = (username) => {
  const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
  return usernameRegex.test(username);
};

const isPasswordStrong = (password) => {
  return passwordStrength(password).value?.toLowerCase() === 'strong';
};

module.exports = {
  isEmailValid,
  isUsernameValid,
  isPasswordStrong
};
