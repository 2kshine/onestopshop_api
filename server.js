const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { sequelize } = require('./models/index.js');
const routes = require('./src/routes/index.js');
const { sixDigitCodeRedis } = require('./src/services/redis-connect.js');
require('dotenv').config();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(cors());
app.use(cookieParser(process.env.COOKIE_TOP_SECRET));
app.use('/api', routes);
const PORT = process.env.PORT;

app.use('/', (req, res) => {
  res.send(
    '<h4>You have successfully landed on the sexiest page to see my portfolio!.</h4>'
  );
});

app.listen(PORT, async () => {
  // sequelize.sync({ force: true });
  console.log(typeof await sixDigitCodeRedis('userId', 'get', 'something1234'));

  sequelize
    .authenticate()
    .then(() => console.log('Successfully made connection to the database.'));

  console.log(`Listening at PORT ${PORT}`);
});
