const mongoose = require('mongoose');

const { toJSON, paginate } = require('./plugins');

const dmvRecordsSchema = mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
        },
        DL_no: {
            type: String,
            required: true,
            unique: true,
            trim: true,
        },
        dob: {
            type: String,
            required: true,
            trim: true,
        },
        address: {
            type: String,
            required: true,
            trim: true,
        },
        attestor: {
            type: mongoose.SchemaTypes.ObjectId,
            ref: 'dmv_attestors',
            required: true,
        },
        attestation_status: {
            type: String,
            enum: ['ACCEPTED', 'REJECTED', 'PENDING'],
            default: 'PENDING'
        },
        userId: {
            type: mongoose.SchemaTypes.ObjectId,
            ref: 'NewUser',
            required: true,
            unique: true
        },
        transactionReceipt: {
            type: mongoose.SchemaTypes.ObjectId,
            ref: 'TransactionReceipt'
        }
    },
    {
        timestamps: true,
    }
);
// add plugin that converts mongoose to json
dmvRecordsSchema.plugin(toJSON);
dmvRecordsSchema.plugin(paginate);

const DMV_RECORDS = mongoose.model('DMV_RECORDS', dmvRecordsSchema);

module.exports = DMV_RECORDS;