const aws = require('aws-sdk');
const { DateTime } = require('luxon');
require('dotenv').config();
const { AWS_REGION, AWS_ACCESS_KEY, AWS_SECRET_KEY } = process.env;

const client = new aws.CloudWatchLogs({
  accessKeyId: AWS_ACCESS_KEY,
  secretAccessKey: AWS_SECRET_KEY,
  region: AWS_REGION
});
const logGroupName = 'onestopshop_logs';

const log = (controller, customMessage, req, stream, data) => {
  const currentDateTime = DateTime.now(); // Current date and time in Luxon DateTime object
  const messageParts = [
    `${stream.toUpperCase()}, ${customMessage}`,
    req ? `, ${JSON.stringify({ req: req.headers })}` : '',
    data ? `, ${JSON.stringify(data)}` : ''
  ];
  const message = messageParts.join('');

  const logEvent = {
    logGroupName,
    logStreamName: `stream/${controller}`,
    logEvents: [
      {
        timestamp: currentDateTime.toMillis(),
        message
      }
    ]
  };

  client.putLogEvents(logEvent, (err, data) => {
    if (err) {
      console.error('Failed to log the event:', err);
    }
  });
};

module.exports = { log };
