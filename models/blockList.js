// models/BlockList.js
const mongoose = require('mongoose');

const blockListSchema = new mongoose.Schema({
  blocker: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  blocked: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

// Compound index to ensure a user can't block another user multiple times
blockListSchema.index({ blocker: 1, blocked: 1 }, { unique: true });

module.exports = mongoose.model('BlockList', blockListSchema);
