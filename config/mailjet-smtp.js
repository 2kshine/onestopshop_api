const Mailjet = require('node-mailjet');
const mailjet = new Mailjet({
  apiKey: process.env.MAILJET_API_KEY,
  apiSecret: process.env.MAILJET_SECRET_KEY
});

const MailJetEmailSend = async (emailContent) => {
  try {
    const message =
            await mailjet
              .post('send', { version: 'v3.1' })
              .request({
                Messages: [emailContent]
              });
    if (!message) {
      console.log('mailjet-smpt:MailJetEmailSend | Error occured !!! ', message.response.data);
      return { error: message, response: null };
    } else {
      console.log('mailjet-smpt:MailJetEmailSend | Email Sent Successfully !!! ', message.response.data);
      return { error: null, response: message.response.data };
    }
  } catch (err) {
    console.log('mailjet-smpt:MailJetEmailSend | Error occured while sending email.. !!! ', err);
    return { error: err.response.data, response: null };
  }
};

module.exports = { MailJetEmailSend };
