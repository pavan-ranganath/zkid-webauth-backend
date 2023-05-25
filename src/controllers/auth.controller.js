const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const { authService, userService, tokenService, emailService } = require('../services');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { isoUint8Array } = require('@simplewebauthn/server/helpers');

const { v4: uuidv4 } = require('uuid');
const ed = require('@noble/ed25519');

const ApiError = require('../utils/ApiError');

const base64url = require('base64url');
var libSodiumWrapper = require("libsodium-wrappers");

var tweetnaclUtil = require("tweetnacl-util");

// const { generateKeyPair, encrypt, signEncode, verifySign, sign, getSharedKey, decrypt, encryptWithSharedKey, decryptWithShared } = require('../middlewares/ed25519Wrapper')

const { sign, generateKeyPair, readOpenSslPublicKeys, verifySign, getSharedKey, encryptWithSharedKey, convertEd25519PublicKeyToCurve25519, convertEd25519PrivateKeyToCurve25519, decryptWithSharedKey } = require('../middlewares/ed25519NewWrapper')
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
  await authService.checkEmailExists(email);
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
  req.session.user = { email: email, userId: userId }
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
      expectedOrigin: origin,
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
    const user = await userService.createUser({ uniqueId: userInSession.userId, name: userInSession.email, email: userInSession.email, devices: [newDevice] });
  }
  req.session.currentChallenge = undefined;
  res.status(httpStatus.CREATED).send({ verified });
});

const SimpleWebAuthnLogin = catchAsync(async (req, res) => {
  let user = await authService.loginWithEmail(req.query.email);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  const opts = {
    timeout: 60000,
    allowCredentials: user.devices.map(dev => ({
      id: dev.credentialID.buffer,
      type: 'public-key',
      transports: dev.transports,
    })),
    userVerification: 'required',
    rpID,
  };
  const options = generateAuthenticationOptions(opts);

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  req.session.user = user
  req.session.currentChallenge = options.challenge;
  res.send(options);
});

const SimpleWebAuthnLoginVerify = catchAsync(async (req, res) => {
  const body = req.body;
  const user = req.session.user;
  const expectedChallenge = req.session.currentChallenge;
  let dbAuthenticator;
  const bodyCredIDBuffer = base64url.toBuffer(body.rawId);
  // "Query the DB" here for an authenticator matching `credentialID`
  for (const dev of user.devices) {
    if (isoUint8Array.areEqual(base64url.toBuffer(dev.credentialID), bodyCredIDBuffer)) {
      dbAuthenticator = dev;
      break;
    }
  }

  if (!dbAuthenticator) {
    return res.status(400).send({ error: 'Authenticator is not registered with this site' });
  }
  let verification;
  try {
    const opts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialPublicKey: base64url.toBuffer(dbAuthenticator.credentialPublicKey),
        credentialID: base64url.toBuffer(dbAuthenticator.credentialID),
        counter: dbAuthenticator.counter,
        transports: dbAuthenticator.transports
      },
      requireUserVerification: true,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the authenticator's counter in the DB to the newest count in the authentication
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  req.session.currentChallenge = undefined;

  res.send({ verified });
});

const EntadaAuthRegistration = catchAsync(async (req, res) => {
  const body = req.body;
  const username = body.username;
  const { ephemeralKeyPair, userId, challengeEncrypt, signedChallengeEncrypt } = await authService.entradaAuthRegistration(body, username, req);
  console.log("ephemeralKeyPair.publicKey", ephemeralKeyPair.publicKey)
  const respObj = {
    challengeEncrypt: challengeEncrypt,
    signedChallengeEncrypt: signedChallengeEncrypt.toHex(),
    ephemeralPubKey: Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    userId: userId
  }
  res.send(respObj)
});


const EntadaAuthRegistrationVerify = catchAsync(async (req, res) => {
  const body = req.body;
  const encryptedData = body.encryptedData;
  const signature = body.signature;
  // console.log(req.session);

  if (req.session.user) {
    let user = req.session.user
    let keyStore = req.session.keystore
    let sharedKey = Buffer.from(keyStore.sharedKey, "base64")
    // VERIFY SIGNATURE USING USER PUBLIC KEY
    const clientPublicKey = readOpenSslPublicKeys(user.publicKey)
    if (!verifySign(signature, encryptedData, clientPublicKey)) {
      return res.status(400).send({ error: "Signature verification failed" });
    }

    // DECRYPT THE CHALLENGE USING SHARED KEY

    let decryptedChallenge = decryptWithSharedKey(encryptedData, sharedKey)
    let challengeObj = JSON.parse(decryptedChallenge)
    // COMPARE CHALLENGE
    if (challengeObj.challenge != user.challenge) {
      return res.status(400).send({ error: "Challenge verification failed" });
    }
    // GENERATE REGISTRATION CODE
    let registrationCode = generate6digitRandomNumber()

    // ENCRYPT REGISTRATION CODE
    let encryptedRegistrationCode = encryptWithSharedKey(registrationCode.toString(), sharedKey)

    // CREATE USER IN DB
    const createUser = await userService.entradaMethodCreateUser({ ...user, registrationCode: registrationCode });

    // SEND ENCRYPTED REGISTRATION CODE AND USER INFO
    const respObj = {
      registrationCode: encryptedRegistrationCode,
      userId: user.userId
    }
    const verifyEmailToken = await tokenService.generateVerifyEmailToken(createUser);
    await emailService.sendVerificationEmail(createUser.username, verifyEmailToken);

    res.send(respObj)
  }
})

const EntadaAuthLogin = catchAsync(async (req, res) => {
  const body = req.body;
  const username = body.username;
  const plainMsg = body.plainMsg;
  const signature = body.signature;
  let {user, ephemeralKeyPair, sharedKey} = await authService.loginUsingPublicKey(username, plainMsg, signature);

  
  // CREATE SESSION
  req.session.user = user
  req.session.keystore = { ephemeralKeyPair: ephemeralKeyPair, sharedKey }

  const respObj = {
    ephemeralPubKey: Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    user: user
  }
  return res.status(200).send({ status: "success", ...respObj })
})

function generate6digitRandomNumber() {
  var minm = 100000;
  var maxm = 999999;
  return Math.floor(Math
  .random() * (maxm - minm + 1)) + minm;
}
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
  SimpleWebAuthnVerifyRegistration,
  SimpleWebAuthnLogin,
  SimpleWebAuthnLoginVerify,
  EntadaAuthRegistration,
  EntadaAuthRegistrationVerify,
  EntadaAuthLogin
};


