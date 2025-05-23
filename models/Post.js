const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
  user: {
    _id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    username: {
      type: String,
      required: true
    },
    profilePicture: {
      type: String,
      default: null
    }
  },
  text: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: String,
  imageUrl: String,
  region: {
    type: String,
    default: 'All'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  upvotes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  comments: [commentSchema]
});

module.exports = mongoose.model('Post', postSchema);
