const httpStatus = require('http-status');
const { DMVAttestor } = require('../models');
const ApiError = require('../utils/ApiError');
/**
 * Create a dmv record
 * @param {Object} dmvAttestorBody
 * @returns {Promise<DMVAttestor>}
 */
const createDMVAttestor = async (dmvAttestorBody) => {
    return DMVAttestor.create(dmvAttestorBody);
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
const queryDMVAttestors = async (filter, options) => {
    const DMVAttestors = await DMVAttestor.paginate(filter, options);
    return DMVAttestors;
};

/**
 * Get DMV record by id
 * @param {ObjectId} id
 * @returns {Promise<DMVAttestor>}
 */
const getDMVAttestorById = async (id) => {
    return DMVAttestor.findById(id);
};


/**
 * Update DMV record by id
 * @param {ObjectId} dmvId
 * @param {Object} updateBody
 * @returns {Promise<DMVAttestor>}
 */
const updateDMVAttestorById = async (DMVId, updateBody) => {
    const dmv = await getDMVAttestorById(DMVId);
    if (!dmv) {
        throw new ApiError(httpStatus.NOT_FOUND, 'DMV Record not found');
    }
    Object.assign(dmv, updateBody);
    await dmv.save();
    return dmv;
};

/**
 * Delete user by id
 * @param {ObjectId} dmvId
 * @returns {Promise<DMVAttestor>}
 */
const deleteDMVAttestorById = async (dmvId) => {
    const dmv = await getDMVAttestorById(dmvId);
    if (!dmv) {
      throw new ApiError(httpStatus.NOT_FOUND, 'DMV Record not found');
    }
    await dmv.remove();
    return dmv;
  };

  module.exports = {
    createDMVAttestor,
    queryDMVAttestors,
    getDMVAttestorById,
    updateDMVAttestorById,
    deleteDMVAttestorById,
  };