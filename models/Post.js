const mongoose = require('mongoose');

// Define the schema for comments
const commentSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // Reference to the User model
    required: true
  },
  username: { // Denormalized username for easier display
    type: String,
    required: true
  },
  profilePicture: { // Denormalized profile picture URL for easier display
    type: String,
    default: '/images/default-profile.jpg' // Default image if user has no picture
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

// Define the main post schema
const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  content: {
    type: String,
    required: true
  },
  imageUrl: {
    type: String,
    default: '' // Default empty string if no image URL is provided
  },
  author: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now // Default to current date and time
  },
  region: {
    type: String,
    default: 'All' // Default region if not specified
  },
  upvotes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User' // Array of User ObjectIds who upvoted
  }],
  comments: [commentSchema] // Array of embedded comment documents
});

module.exports = mongoose.model('Post', postSchema);
