const mongoose = require('mongoose');

const { toJSON,paginate } = require('./plugins');

const dmvAttestorsSchema = mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
        },
        publicAddress: {
            type: String,
            required: true,
            trim: true,
        }
    },
    {
        timestamps: true,
    }
);
// add plugin that converts mongoose to json
dmvAttestorsSchema.plugin(toJSON);
dmvAttestorsSchema.plugin(paginate);

const DMV_ATTESTORS = mongoose.model('dmv_attestors', dmvAttestorsSchema);

module.exports = DMV_ATTESTORS;