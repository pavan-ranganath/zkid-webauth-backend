const httpStatus = require('http-status');
const tokenService = require('./token.service');
const userService = require('./user.service');
const emailService = require('./email.service');

const Token = require('../models/token.model');
const ApiError = require('../utils/ApiError');
const { tokenTypes } = require('../config/tokens');
// const { generateKeyPair, signEncode, verifySign, sign, getSharedKey,encryptWithSharedKey, decryptWithShared } = require('../middlewares/ed25519Wrapper')
const { sign, generateKeyPair, readOpenSslPublicKeys, verifySign, getSharedKey, encryptWithSharedKey, convertEd25519PublicKeyToCurve25519, convertEd25519PrivateKeyToCurve25519 } = require('../middlewares/ed25519NewWrapper')

var tweetnaclUtil = require("tweetnacl-util");
const { v4: uuidv4 } = require('uuid');
const ed = require('@noble/ed25519');

var libSodiumWrapper = require("libsodium-wrappers");

/**
 * Login with username and password
 * @param {string} email
 * @param {string} password
 * @returns {Promise<User>}
 */
const loginUserWithEmailAndPassword = async (email, password) => {
  const user = await userService.getUserByEmail(email);
  if (!user || !(await user.isPasswordMatch(password))) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Incorrect email or password');
  }
  return user;
};

/**
 * Logout
 * @param {string} refreshToken
 * @returns {Promise}
 */
const logout = async (refreshToken) => {
  const refreshTokenDoc = await Token.findOne({ token: refreshToken, type: tokenTypes.REFRESH, blacklisted: false });
  if (!refreshTokenDoc) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Not found');
  }
  await refreshTokenDoc.remove();
};

/**
 * Refresh auth tokens
 * @param {string} refreshToken
 * @returns {Promise<Object>}
 */
const refreshAuth = async (refreshToken) => {
  try {
    const refreshTokenDoc = await tokenService.verifyToken(refreshToken, tokenTypes.REFRESH);
    const user = await userService.getUserById(refreshTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await refreshTokenDoc.remove();
    return tokenService.generateAuthTokens(user);
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate');
  }
};

/**
 * Reset password
 * @param {string} resetPasswordToken
 * @param {string} newPassword
 * @returns {Promise}
 */
const resetPassword = async (resetPasswordToken, newPassword) => {
  try {
    const resetPasswordTokenDoc = await tokenService.verifyToken(resetPasswordToken, tokenTypes.RESET_PASSWORD);
    const user = await userService.getUserById(resetPasswordTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await userService.updateUserById(user.id, { password: newPassword });
    await Token.deleteMany({ user: user.id, type: tokenTypes.RESET_PASSWORD });
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Password reset failed');
  }
};

/**
 * Verify email
 * @param {string} verifyEmailToken
 * @returns {Promise}
 */
const verifyEmail = async (verifyEmailToken) => {
  try {
    const verifyEmailTokenDoc = await tokenService.verifyToken(verifyEmailToken, tokenTypes.VERIFY_EMAIL);
    const user = await userService.getUserById(verifyEmailTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await Token.deleteMany({ user: user.id, type: tokenTypes.VERIFY_EMAIL });
    await userService.updateUserById(user.id, { isEmailVerified: true });
  } catch (error) {
    console.error(error);
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Email verification failed');
  }
};

/**
 * Login with email 
 * @param {string} email
 * @returns {Promise<User>}
 */
const loginWithEmail = async (email) => {
  const user = await userService.getUserByEmail(email);
  return user;
};

/**
 * Check email exists
 * @param {string} email
 * @returns {Promise<User>}
 */
const checkEmailExists = async (email) => {
  await userService.checkEmailExists(email);
};

/**
 * Check email exists
 * @param {string} email
 * @returns {Promise<User>}
 */
const loginUsingPublicKey = async (username, plainMsg, signedMsg) => {
  await userService.checkEmailEntradaCustomUser(username);
  let user = await userService.getEntradaAuthUserByEmail(username)
  // VERIFY SIGNATURE USING USER PUBLIC KEY
  if (!verifySign(signedMsg, plainMsg, (user.publicKey))) {
    throw new ApiError(httpStatus.UNAUTHORIZED, "Signature verification failed");
  }

  // Check of email has been verified
  if (!user.isEmailVerified) {
    const verifyEmailToken = await tokenService.generateVerifyEmailToken(user);
    await emailService.sendVerificationEmail(user.username, verifyEmailToken);
    // throw new ApiError(httpStatus.UNAUTHORIZED, 'Please verify your email address');
  }

  return user
};

async function entradaAuthRegistration(body, username, req) {
  const userPublicKey = body.publicKey;
  const signedMsg = body.signedMsg;
  const plainMsg = body.plainMsg;

  // CHECK USER EXISTS
  await userService.checkEmailEntradaCustomUser(username, userPublicKey);

  // VALIDATE SIGNATURE
  const clientPublicKey = readOpenSslPublicKeys(userPublicKey)
  if (!verifySign(signedMsg, plainMsg, clientPublicKey)) {
    throw new Error('Signature verification failed');
  }


  const userId = uuidv4();
  // GENERATE CHALLENGE
  const challenge = ed.utils.bytesToHex(ed.utils.randomPrivateKey());
  console.log("challenge", challenge)

  //GENERTE EPHEMERAL KEY
  const ephemeralKeyPair = generateKeyPair();
  console.log("serverPrivateKey",Buffer.from(ephemeralKeyPair.secretKey).toString('base64'));
  console.log("serverPublicKey", Buffer.from(ephemeralKeyPair.publicKey).toString('base64'));

  // ED25519 -> curve25519
  const clientCurve25519PublicKey = convertEd25519PublicKeyToCurve25519(clientPublicKey)
  const ServerCurve25519PrivateKey = convertEd25519PrivateKeyToCurve25519(ephemeralKeyPair.secretKey)

  // GENERATE SHARED SECRET
  const sharedKey = getSharedKey(ServerCurve25519PrivateKey, clientCurve25519PublicKey);
  console.log('Server shared key (Base64):', Buffer.from(sharedKey).toString('base64'));

  // ENCRYPT CHALLENGE USING USER PUBLIC KEY
  const challengeEncrypt = encryptWithSharedKey(challenge, sharedKey);

  const signedChallengeEncrypt = sign(challengeEncrypt, ephemeralKeyPair.secretKey)
  // let verifyMsg =  verifySign(challengeEncrypt,signedChallengeEncrypt,ephemeralKeyPair.publicKey)

  // CREATE SESSION
  req.session.user = { ...body, userId: userId, challenge: challenge };
  req.session.keystore = {
    publicKey:  Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    privateKey: Buffer.from(ephemeralKeyPair.secretKey).toString('base64'),
    sharedKey: Buffer.from(sharedKey).toString('base64')
  };
  return { ephemeralKeyPair, userId, challengeEncrypt, signedChallengeEncrypt };
}
module.exports = {
  loginUserWithEmailAndPassword,
  logout,
  refreshAuth,
  resetPassword,
  verifyEmail,
  loginWithEmail,
  checkEmailExists,
  loginUsingPublicKey,
  entradaAuthRegistration
};
