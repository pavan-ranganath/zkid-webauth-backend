const httpStatus = require('http-status');
const { DMVRecord, TransactionReceipt } = require('../models');
const ApiError = require('../utils/ApiError');
/**
 * Create a dmv record
 * @param {Object} dmvBody
 * @returns {Promise<DMVRecord>}
 */
const createDMVRecord = async (dmvBody) => {
    return DMVRecord.create(dmvBody);
};

/**
 * Query for DMV records
 * @param {Object} filter - Mongo filter
 * @param {Object} options - Query options
 * @param {string} [options.sortBy] - Sort option in the format: sortField:(desc|asc)
 * @param {number} [options.limit] - Maximum number of results per page (default = 10)
 * @param {number} [options.page] - Current page (default = 1)
 * @returns {Promise<QueryResult>}
 */
const queryDMVRecords = async (filter, options) => {
    const dmvRecords = await DMVRecord.paginate(filter, options);
    return dmvRecords;
};

/**
 * Get DMV record by id
 * @param {ObjectId} id
 * @returns {Promise<DMVRecord>}
 */
const getDMVRecordById = async (id) => {
    return DMVRecord.findById(id);
};

/**
 * Get DMV record by user id
 * @param {ObjectId} userId
 * @returns {Promise<DMVRecord>}
 */
const getDMVRecordByUserId = async (_userId) => {
    return DMVRecord.findOne({userId:_userId});
};

/**
 * Update DMV record by id
 * @param {ObjectId} dmvId
 * @param {Object} updateBody
 * @returns {Promise<DMVRecord>}
 */
const updateDmvRecordById = async (DMVId, updateBody) => {
    const dmv = await getDMVRecordById(DMVId);
    if (!dmv) {
        throw new ApiError(httpStatus.NOT_FOUND, 'DMV Record not found');
    }
    if(updateBody.transactionReceipt) {
        const trans = await TransactionReceipt.create(updateBody.transactionReceipt)
        updateBody.transactionReceipt = trans.id;
    }
    Object.assign(dmv, updateBody);
    await dmv.save();
    return dmv;
};

/**
 * Delete user by id
 * @param {ObjectId} dmvId
 * @returns {Promise<DMVRecord>}
 */
const deleteDmvRecordById = async (dmvId) => {
    const dmv = await getDMVRecordById(dmvId);
    if (!dmv) {
      throw new ApiError(httpStatus.NOT_FOUND, 'DMV Record not found');
    }
    await dmv.remove();
    return dmv;
  };

  module.exports = {
    createDMVRecord,
    queryDMVRecords,
    getDMVRecordById,
    updateDmvRecordById,
    deleteDmvRecordById,
    getDMVRecordByUserId
  };