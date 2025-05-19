const mongoose = require('mongoose');

const registrationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  fullname: {
    type: String,
    required: true
  },
  teamMembers: String,
  category: {
    type: String,
    required: true
  },
  school: String,
  address: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  competition: [String],
  workshop: {
    type: [String],
    required: true
  },
  other_competition: String,
  other_workshop: String,
  code: String,
  paymentProofUrl: String,
  payment_details: String,
  registeredAt: {
    type: Date,
    default: Date.now
  },
  verified: {
    type: Boolean,
    default: false
  },
  verifiedBy: String,
  verifiedAt: Date,
  denied: {
    type: Boolean,
    default: false
  },
  deniedReason: {
    type: String,
    enum: [
      'Invalid payment receipt', 
      'Amount on receipt does not match amount received', 
      'Amount on payment details does not match amount on receipt',
      'Other'
    ]
  },
  deniedMessage: String,
  deniedBy: String,
  deniedAt: Date
});

module.exports = mongoose.model('Registration', registrationSchema); 