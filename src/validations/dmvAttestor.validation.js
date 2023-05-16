const Joi = require('joi');
const { objectId } = require('./custom.validation');
const createDMVAttestor = {
    body: Joi.object().keys({
        name: Joi.string().required(),
        publicAddress: Joi.string().required()
    }),

};

const getDMVAttestors = {
    query: Joi.object().keys({
        sortBy: Joi.string(),
        limit: Joi.number().integer(),
        page: Joi.number().integer(),
    }),
};

const getDMVAttestor = {
    params: Joi.object().keys({
        id: Joi.string().custom(objectId),
    }),
};


const updateDMVAttestor = {
    params: Joi.object().keys({
        id: Joi.required().custom(objectId),
    }),
    body: Joi.object()
        .keys({
            name: Joi.string().required(),
        })
        .min(1),
};
const deleteDMVAttestor = {
    params: Joi.object().keys({
        id: Joi.string().custom(objectId),
    }),
};

module.exports = {
    createDMVAttestor,
    getDMVAttestors,
    getDMVAttestor,
    updateDMVAttestor,
    deleteDMVAttestor,
};
