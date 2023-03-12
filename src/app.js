const express = require('express');
const helmet = require('helmet');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const cors = require('cors');
const passport = require('passport');
const httpStatus = require('http-status');
const config = require('./config/config');
const morgan = require('./config/morgan');
const { jwtStrategy } = require('./config/passport');
const { authLimiter } = require('./middlewares/rateLimiter');
const routes = require('./routes/v1');
const { errorConverter, errorHandler } = require('./middlewares/error');
const ApiError = require('./utils/ApiError');
var session = require('express-session')
const MemoryStore = require('memorystore')(session)
var cookieParser = require('cookie-parser')

const app = express();

if (config.env !== 'test') {
  app.use(morgan.successHandler);
  app.use(morgan.errorHandler);
}

// set security HTTP headers
// app.use(helmet());

// parse json request body
app.use(express.json());


// // parse urlencoded request body
app.use(express.urlencoded({ extended: true }));

// sanitize request data
app.use(xss());
app.use(mongoSanitize());

// gzip compression
app.use(compression());

// enable cors
app.use(cors());
app.options('*', cors());


app.use(
  session(
    {
    secret: 'b24ed0f617408d34f1d744095c752f3326699ad46fff89591aeb664237b5c1514',
    resave: false,
    saveUninitialized: true,
    cookie: {
      sameSite: true,
      
      secure:false,
      maxAge: 360000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000, // prune expired entries every 24h
    }),
  }
  ),
);
// jwt authentication
app.use(passport.initialize());
// app.use(passport.session());
passport.use('jwt', jwtStrategy);
// app.use(function(request, response, next) {
//   if (request.session && !request.session.regenerate) {
//       request.session.regenerate = (cb) => {
//           cb()
//       }
//   }
//   if (request.session && !request.session.save) {
//       request.session.save = (cb) => {
//           cb()
//       }
//   }
//   next()
// })

// limit repeated failed requests to auth endpoints
if (config.env === 'production') {
  app.use('/v1/auth', authLimiter);
}

// v1 api routes
app.use('/v1', routes);

// send back a 404 error for any unknown api request
app.use((req, res, next) => {
  next(new ApiError(httpStatus.NOT_FOUND, 'Not found'));
});

// convert error to ApiError, if needed
app.use(errorConverter);

// handle error
app.use(errorHandler);

module.exports = app;
