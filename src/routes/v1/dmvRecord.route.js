const express = require('express');
const auth = require('../../middlewares/auth');
const validate = require('../../middlewares/validate');
const dmvRecordValidation = require('../../validations/dmvRecord.validation');
const dmvRecordController = require('../../controllers/dmv.controller');

const router = express.Router();

router
  .route('/')
  .post(validate(dmvRecordValidation.createDMVRecord), dmvRecordController.createDMVRecord)
  .get(validate(dmvRecordValidation.getDMVRecords), dmvRecordController.getDMVRecords);

router
  .route('/:id')
  .get(validate(dmvRecordValidation.getDMVRecord), dmvRecordController.getDMVRecord)
  .patch(validate(dmvRecordValidation.updateDMVRecord), dmvRecordController.updateDMVRecord)
  .delete(validate(dmvRecordValidation.deleteDMVRecord), dmvRecordController.deleteDMVRecord);

  router
  .route('/user/:id')
  .get(validate(dmvRecordValidation.getDMVRecord), dmvRecordController.getDMVRecordByUserId)
  

module.exports = router;