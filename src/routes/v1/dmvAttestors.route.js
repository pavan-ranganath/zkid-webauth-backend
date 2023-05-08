const express = require('express');
const auth = require('../../middlewares/auth');
const validate = require('../../middlewares/validate');
const dmvAttestorController = require('../../controllers/dmvAttestors.controller');
const dmvAttestorValidation = require('../../validations/dmvAttestor.validation');

const router = express.Router();

router
  .route('/')
  .post(validate(dmvAttestorValidation.createDMVAttestor), dmvAttestorController.createDMVAttestor)
  .get(validate(dmvAttestorValidation.getDMVAttestors), dmvAttestorController.getDMVAttestors);

router
  .route('/:id')
  .get(validate(dmvAttestorValidation.getDMVAttestor), dmvAttestorController.getDMVAttestor)
  .patch(validate(dmvAttestorValidation.updateDMVAttestor), dmvAttestorController.updateDMVAttestor)
  .delete(validate(dmvAttestorValidation.deleteDMVAttestor), dmvAttestorController.deleteDMVAttestor);

module.exports = router;