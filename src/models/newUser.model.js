const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const { toJSON, paginate } = require('./plugins');
const { roles } = require('../config/roles');

const newUserSchema = mongoose.Schema(
  {
    userId: {
      type: String,
      required: true,
      trim: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      validate(value) {
        if (!validator.isEmail(value)) {
          throw new Error('Invalid email');
        }
      },
    },
    publicKey: {
      type: String,
      required: true,
      trim: true,
    },
    registrationCode: {
      type: String,
      required: true,
      trim: true,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// add plugin that converts mongoose to json
newUserSchema.plugin(toJSON);
newUserSchema.plugin(paginate);

/**
 * Check if email is taken
 * @param {string} email - The user's email
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
newUserSchema.statics.isEmailTaken = async function (email) {
  const user = await this.findOne({email});
  return !!user;
};


/**
 * Check if public key is taken
 * @param {string} publicKey - The user's public key
 * @returns {Promise<boolean>}
 */
newUserSchema.statics.isPublicKeyTaken = async function (publicKey) {
  const user = await this.findOne({publicKey});
  return !!user;
};

/**
 * @typedef NewUser
 */
const NewUser = mongoose.model('NewUser', newUserSchema);

module.exports = NewUser;
