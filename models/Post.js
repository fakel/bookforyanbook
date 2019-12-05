const Joi = require('@hapi/joi');
const mongoose = require('mongoose');

const { ObjectId } = mongoose.Schema;

const BookPost = new mongoose.Schema({
  author: {
    type: String,
    required: true,
    minlength: 5,
    maxlength: 50,
  },
  creator: {
    type: ObjectId,
    required: true,
  },
  slug: {
    type: String,
    lowercase: true,
    trim: true,
  },
  date: {
    type: Date,
    required: true,
    default: Date.now(),
  },
  public: {
    type: Boolean,
    required: true,
    default: true,
  },
});

const Post = mongoose.model('Post', BookPost);

function validatePost(user) {
  const schema = Joi.object().keys({
    slug: Joi.string()
      .trim(true)
      .min(5)
      .max(150)
      .required(),
  });

  return schema.validate(user);
}

exports.Post = Post;
exports.validatePost = validatePost;
