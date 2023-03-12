const Joi = require('joi');
const { password } = require('./custom.validation');

const register = {
  body: Joi.object().keys({
    email: Joi.string().required().email(),
    password: Joi.string().required().custom(password),
    name: Joi.string().required(),
  }),
};

const login = {
  body: Joi.object().keys({
    email: Joi.string().required(),
    password: Joi.string().required(),
  }),
};

const logout = {
  body: Joi.object().keys({
    refreshToken: Joi.string().required(),
  }),
};

const refreshTokens = {
  body: Joi.object().keys({
    refreshToken: Joi.string().required(),
  }),
};

const forgotPassword = {
  body: Joi.object().keys({
    email: Joi.string().email().required(),
  }),
};

const resetPassword = {
  query: Joi.object().keys({
    token: Joi.string().required(),
  }),
  body: Joi.object().keys({
    password: Joi.string().required().custom(password),
  }),
};

const verifyEmail = {
  query: Joi.object().keys({
    token: Joi.string().required(),
  }),
};

const simpleWebAuthnRegistration = {
  query: Joi.object().keys({
    email: Joi.string().email().required(),
  }),
};

const entradaAuthRegistration = {
  body: Joi.object().keys({
    username: Joi.string().email().required(),
    name: Joi.string().required(),
    publicKey: Joi.string().required(),
  }),
};
const entradaAuthRegistrationVerify = {
  body: Joi.object().keys({
    plainMsg: Joi.string().required(),
    signedMsg: Joi.string().required(),
    encryptedChallengeWithShared: Joi.string().required(),
    nonce: Joi.string().required(),
  }),
};


module.exports = {
  register,
  login,
  logout,
  refreshTokens,
  forgotPassword,
  resetPassword,
  verifyEmail,
  simpleWebAuthnRegistration,
  entradaAuthRegistration,
  entradaAuthRegistrationVerify
};
