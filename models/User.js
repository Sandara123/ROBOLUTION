const mongoose = require('mongoose');
const speakeasy = require('speakeasy');

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true
  },
  username: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  birthDate: {
    month: {
      type: Number,
      min: 1,
      max: 12
    },
    year: {
      type: Number
    }
  },
  school: {
    type: String
  },
  profilePicture: {
    type: String,
    default: '' // URL to default profile image
  },
  address: {
    type: String
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  twoFactorSecret: {
    type: String,
    default: function() {
      const secret = speakeasy.generateSecret({
        length: 20,
        name: `Robolution:${this.username || 'user'}`
      });
      return secret.base32;
    }
  },
  twoFactorEnabled: {
    type: Boolean,
    default: true
  },
  backupCodes: {
    type: [String],
    default: function() {
      return Array(8).fill().map(() => 
        Math.random().toString(36).substring(2, 8).toUpperCase()
      );
    }
  }
});

module.exports = mongoose.model('User', userSchema); 