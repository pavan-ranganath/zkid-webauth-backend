const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const { authService, userService, tokenService, emailService } = require('../services');
const { generateRegistrationOptions,verifyRegistrationResponse } = require('@simplewebauthn/server');
const { v4: uuidv4 } = require('uuid');



// Human-readable title for your website
const rpName = 'Entada test SimpleWebAuthn';
// A unique identifier for your website
const rpID = 'localhost';
// The URL at which registrations and authentications should occur
const origin = `http://${rpID}:4200`;

const register = catchAsync(async (req, res) => {
  const user = await userService.createUser(req.body);
  const tokens = await tokenService.generateAuthTokens(user);
  res.status(httpStatus.CREATED).send({ user, tokens });
});

const login = catchAsync(async (req, res) => {
  const { email, password } = req.body;
  const user = await authService.loginUserWithEmailAndPassword(email, password);
  const tokens = await tokenService.generateAuthTokens(user);
  res.send({ user, tokens });
});

const logout = catchAsync(async (req, res) => {
  await authService.logout(req.body.refreshToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const refreshTokens = catchAsync(async (req, res) => {
  const tokens = await authService.refreshAuth(req.body.refreshToken);
  res.send({ ...tokens });
});

const forgotPassword = catchAsync(async (req, res) => {
  const resetPasswordToken = await tokenService.generateResetPasswordToken(req.body.email);
  await emailService.sendResetPasswordEmail(req.body.email, resetPasswordToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const resetPassword = catchAsync(async (req, res) => {
  await authService.resetPassword(req.query.token, req.body.password);
  res.status(httpStatus.NO_CONTENT).send();
});

const sendVerificationEmail = catchAsync(async (req, res) => {
  const verifyEmailToken = await tokenService.generateVerifyEmailToken(req.user);
  await emailService.sendVerificationEmail(req.user.email, verifyEmailToken);
  res.status(httpStatus.NO_CONTENT).send();
});

const verifyEmail = catchAsync(async (req, res) => {
  await authService.verifyEmail(req.query.token);
  res.status(httpStatus.NO_CONTENT).send();
});

const SimpleWebAuthnRegistration = catchAsync(async (req, res) => {
  const email = req.query.email;
  await authService.checkEmail(email);
  const userId = uuidv4();
  const opts = {
    rpName: rpName,
    rpID,
    userID: userId,
    userName: email,
    timeout: 60000,
    attestationType: 'none',
    // /**
    //  * Passing in a user's list of already-registered authenticator IDs here prevents users from
    //  * registering the same device multiple times. The authenticator will simply throw an error in
    //  * the browser if it's asked to perform registration when one of these ID's already resides
    //  * on it.
    //  */
    // excludeCredentials: devices.map(dev => ({
    //   id: dev.credentialID,
    //   type: 'public-key',
    //   transports: dev.transports,
    // })),
    authenticatorSelection: {
      residentKey: 'discouraged',
    },


    /**
     * Support the two most common algorithms: ES256, and RS256
     */
    supportedAlgorithmIDs: [-7, -257],
  };

  const options = generateRegistrationOptions(opts);

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  req.session.currentChallenge = options.challenge;
  req.session.user = {email:email,userId:userId}
  return res.send(options);
});

const SimpleWebAuthnVerifyRegistration = catchAsync(async (req, res) => {
  const body = req.body;
  const expectedChallenge = req.session.currentChallenge;
  let verification;
  try {
    const opts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin:origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }
  const { verified, registrationInfo } = verification;
  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;
    const newDevice = {
      credentialPublicKey,
      credentialID,
      counter,
      transports: body.response.transports,
    };
    const userInSession = req.session.user;
    const user = await userService.createUser({uniqueId:userInSession.userId,name:userInSession.email,email:userInSession.email,devices:[newDevice]});
  }
  req.session.currentChallenge = undefined;
  res.status(httpStatus.CREATED).send({ verified });
})
module.exports = {
  register,
  login,
  logout,
  refreshTokens,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
  SimpleWebAuthnRegistration,
  SimpleWebAuthnVerifyRegistration
};
