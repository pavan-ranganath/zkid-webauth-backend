const mongoose = require('mongoose');

const { toJSON, paginate } = require('./plugins');

const transactionReceiptSchema = mongoose.Schema(
    {
        status: {
            type: Boolean,

        },
        transactionHash: {
            type: String,

        },
        transactionIndex: {
            type: Number,

        },
        blockHash: {
            type: String,

        },
        blockNumber: {
            type: Number,

        },
        from: {
            type: String,

        },
        to: {
            type: String,

        },
        contractAddress: {
            type: String,

        },
        cumulativeGasUsed: {
            type: Number,

        },
        gasUsed: {
            type: Number,

        },
        logs: {},
        logsBloom: {
            type: String,

        },
        events: {}
    },
    {
        timestamps: true,
    }
);
// add plugin that converts mongoose to json
transactionReceiptSchema.plugin(toJSON);
transactionReceiptSchema.plugin(paginate);

const TransactionReceipt = mongoose.model('TransactionReceipt', transactionReceiptSchema);

module.exports = TransactionReceipt;