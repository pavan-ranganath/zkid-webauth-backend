const httpStatus = require('http-status');
const tokenService = require('./token.service');
const userService = require('./user.service');
const emailService = require('./email.service');

const Token = require('../models/token.model');
const ApiError = require('../utils/ApiError');
const { tokenTypes } = require('../config/tokens');
const { generateKeyPair, encrypt, signEncode, verifySign, sign, getSharedKey, decrypt,encryptWithSharedKey, decryptWithShared } = require('../middlewares/ed25519Wrapper')
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
   if (!verifySign(signedMsg, plainMsg, tweetnaclUtil.decodeBase64(user.publicKey))) {
    return res.status(400).send({ error: "Signature verification failed" });
  }
  if (!user.isEmailVerified) {
    const verifyEmailToken = await tokenService.generateVerifyEmailToken(user);
    await emailService.sendVerificationEmail(user.username, verifyEmailToken);
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Please verify your email address');
  }
 
  return user
};

async function entradaAuthRegistration(body, username, req) {
  const userPublicKey = body.publicKey;
  const userId = uuidv4();
  // GENERATE CHALLENGE
  const challenge = ed.utils.bytesToHex(ed.utils.randomPrivateKey());

  //GENERTE EPHEMERAL KEY
  const ephemeralKeyPair = await generateKeyPair("hex");

  // ENCRYPT CHALLENGE USING USER PUBLIC KEY
  challengeEncrypt = encrypt(challenge, userPublicKey);

  // GENERATE SHARED SECRET
  const sharedKey = getSharedKey(ephemeralKeyPair.privateKey, userPublicKey);

  // CHECK USER EXISTS
  await userService.checkEmailEntradaCustomUser(username);

  // CREATE SESSION
  req.session.user = { ...body, userId: userId, challenge: challenge };
  req.session.keystore = {
    publicKey: ephemeralKeyPair.publicKey,
    privateKey: ephemeralKeyPair.privateKey,
    keyType: ephemeralKeyPair.keyType,
    sharedKey: sharedKey
  };
  return { ephemeralKeyPair, userId, challengeEncrypt };
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
