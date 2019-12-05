/* eslint-disable no-underscore-dangle */
const Joi = require('@hapi/joi');
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    minlength: 5,
    maxlength: 50,
  },
  email: {
    type: String,
    required: true,
    minlength: 5,
    maxlength: 255,
    unique: true,
    collation: { locale: 'en', strength: 2 },
  },
  password: {
    type: String,
    required: true,
    minlength: 5,
    maxlength: 1024,
  },
  friends: [mongoose.Schema.ObjectId],
});

const User = mongoose.model('User', UserSchema);

function validateUser(user) {
  const schema = Joi.object().keys({
    name: Joi.string()
      .min(5)
      .max(50)
      .required(),
    email: Joi.string()
      .min(5)
      .max(255)
      .required()
      .email(),
    password: Joi.string()
      .min(5)
      .max(255)
      .required(),
  });

  return schema.validate(user);
}

exports.User = User;
exports.validateUser = validateUser;
