const httpStatus = require('http-status');
const pick = require('../utils/pick');
const ApiError = require('../utils/ApiError');
const catchAsync = require('../utils/catchAsync');
const { dmvAttestorService } = require('../services');
const { generateKeyPair, encrypt, signEncode, verifySign, sign, getSharedKey, decrypt, encryptWithSharedKey, decryptWithShared } = require('../middlewares/ed25519Wrapper')
var tweetnaclUtil = require("tweetnacl-util");

const createDMVAttestor = catchAsync(async (req, res) => {
    const body = req.body;
    const dmvAttestor = await dmvAttestorService.createDMVAttestor(body);
    res.status(httpStatus.CREATED).send(dmvAttestor);
});

const getDMVAttestors = catchAsync(async (req, res) => {
    const filter = pick(req.query, ['name']);
    const options = pick(req.query, ['sortBy', 'limit', 'page']);
    const result = await dmvAttestorService.queryDMVAttestors(filter, options);
    res.send(result);
});

const getDMVAttestor = catchAsync(async (req, res) => {
    const result = await dmvAttestorService.getDMVAttestorById(req.params.id);
    if (!result) {
        throw new ApiError(httpStatus.NOT_FOUND, 'DMV Attestor not found');
    }
    res.send(result);
});
const getDMVAttestorByUserId = catchAsync(async (req, res) => {
    const result = await dmvAttestorService.getDMVAttestorByUserId(req.params.id);
    if (!result) {
        throw new ApiError(httpStatus.NOT_FOUND, 'DMV Attestor not found');
    }
    res.send(result);
});
const updateDMVAttestor = catchAsync(async (req, res) => {
    const user = await dmvAttestorService.updateDmvAttestorById(req.params.id, req.body);
    res.send(user);
});

const deleteDMVAttestor = catchAsync(async (req, res) => {
    await userService.deleteDmvAttestorById(req.params.id);
    res.status(httpStatus.NO_CONTENT).send();
});

module.exports = {
    createDMVAttestor,
    getDMVAttestors,
    getDMVAttestor,
    updateDMVAttestor,
    deleteDMVAttestor,
    getDMVAttestorByUserId
  };