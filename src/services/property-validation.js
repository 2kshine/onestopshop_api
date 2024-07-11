const isEmailValid = (emailAddress) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(emailAddress);
};

const isUsernameValid = (username) => {
  const usernameRegex = /\S\s+\S/;
  return !usernameRegex.test(username); // username test passed means it has spaces
};

module.exports = {
  isEmailValid,
  isUsernameValid
};
