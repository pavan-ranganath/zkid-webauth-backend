const Joi = require('joi');
const { objectId } = require('./custom.validation');
const createDMVRecord = {
    body: Joi.object().keys({
        data: {
            name: Joi.string().required(),
            DL_no: Joi.string().required(),
            dob: Joi.string().required(),
            address: Joi.string().required(),
            attestor: Joi.string().required(),
            attestation_status: Joi.string().valid('ACCEPTED', 'REJECTED', 'PENDING'),
            transactionReceipt: Joi.string()
        },
        signedData: Joi.string().required()
    }),
    // body: Joi.object().keys({
    //     data: Joi.string().required(),
    //     nonce: Joi.string().required(),
    // }),
};

const getDMVRecords = {
    query: Joi.object().keys({
        sortBy: Joi.string(),
        limit: Joi.number().integer(),
        page: Joi.number().integer(),
    }),
};

const getDMVRecord = {
    params: Joi.object().keys({
        id: Joi.string().custom(objectId),
    }),
};


const updateDMVRecord = {
    params: Joi.object().keys({
        id: Joi.required().custom(objectId),
    }),
    body: Joi.object()
        .keys({
            id: Joi.string().custom(objectId),
            name: Joi.string().required(),
            DL_no: Joi.string().required(),
            dob: Joi.string().required(),
            address: Joi.string().required(),
            userId: Joi.string(),
            attestor: Joi.string().required(),
            attestation_status: Joi.string().valid('ACCEPTED', 'REJECTED', 'PENDING'),
            transactionReceipt: Joi.object()
        })
        .min(1),
};
const deleteDMVRecord = {
    params: Joi.object().keys({
        id: Joi.string().custom(objectId),
    }),
};

module.exports = {
    createDMVRecord,
    getDMVRecords,
    getDMVRecord,
    updateDMVRecord,
    deleteDMVRecord,
};
