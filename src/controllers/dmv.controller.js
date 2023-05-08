const httpStatus = require('http-status');
const pick = require('../utils/pick');
const ApiError = require('../utils/ApiError');
const catchAsync = require('../utils/catchAsync');
const { dmvService, userService } = require('../services');
const { generateKeyPair, encrypt, signEncode, verifySign, sign, getSharedKey, decrypt, encryptWithSharedKey, decryptWithShared } = require('../middlewares/ed25519Wrapper')
var tweetnaclUtil = require("tweetnacl-util");

const createDMVRecord = catchAsync(async (req, res) => {
    const body = req.body;
    let public_address_header = req.headers['public-address'];
    let user = await userService.getEntradaAuthUserByPublicKey(public_address_header);
    const signedMsg = body.signedData
    const plainData = body.data;
     // VERIFY SIGNATURE USING USER PUBLIC KEY
     if (!verifySign(signedMsg,  JSON.stringify(plainData), tweetnaclUtil.decodeBase64(user.publicKey))) {
        return res.status(400).send({ error: "Signature verification failed" });
      }
    
    const dmvRecord = await dmvService.createDMVRecord({...plainData,userId:user.id});
    res.status(httpStatus.CREATED).send(dmvRecord);
});

const getDMVRecords = catchAsync(async (req, res) => {
    const filter = pick(req.query, ['name']);
    const options = pick(req.query, ['sortBy', 'limit', 'page']);
    const result = await dmvService.queryDMVRecords(filter, options);
    res.send(result);
});

const getDMVRecord = catchAsync(async (req, res) => {
    const result = await dmvService.getDMVRecordById(req.params.id);
    if (!result) {
        throw new ApiError(httpStatus.NOT_FOUND, 'DMV record not found');
    }
    res.send(result);
});
const getDMVRecordByUserId = catchAsync(async (req, res) => {
    const result = await dmvService.getDMVRecordByUserId(req.params.id);
    if (!result) {
        throw new ApiError(httpStatus.NOT_FOUND, 'DMV record not found');
    }
    res.send(result);
});
const updateDMVRecord = catchAsync(async (req, res) => {
    const user = await dmvService.updateDmvRecordById(req.params.id, req.body);
    res.send(user);
});

const deleteDMVRecord = catchAsync(async (req, res) => {
    await userService.deleteDmvRecordById(req.params.id);
    res.status(httpStatus.NO_CONTENT).send();
});

module.exports = {
    createDMVRecord,
    getDMVRecords,
    getDMVRecord,
    updateDMVRecord,
    deleteDMVRecord,
    getDMVRecordByUserId
  };