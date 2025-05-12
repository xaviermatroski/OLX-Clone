const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const lostItemSchema = new Schema({
  name: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  lastSeenLocation: {
    type: String,
    required: true,
  },
  images: [{
    data: String,
    contentType: String
  }],
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['lost', 'found'],
    default: 'lost'
  },
  isResolved: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('LostItem', lostItemSchema);
