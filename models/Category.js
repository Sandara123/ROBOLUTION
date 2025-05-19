const mongoose = require('mongoose');

const CategorySchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  imageUrl: String,
  mechanics: [String],
  generalConduct: [String],
  generalRules: [String],
  participantsRequirement: [String],
  teamRequirement: [String],
  showMechanics: { type: Boolean, default: true },
  showGeneralConduct: { type: Boolean, default: true },
  showGeneralRules: { type: Boolean, default: true },
  showParticipantsRequirement: { type: Boolean, default: true },
  showTeamRequirement: { type: Boolean, default: true }
});

module.exports = mongoose.model('Category', CategorySchema);
