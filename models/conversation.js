const mongoose = require('mongoose');

const ConversationSchema = new mongoose.Schema({
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }],
  messages: [{
    messageId: {
      type: Number,
      default: 1
    },
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    text: {
      type: String,
      required: true
    },
    // For replying to messages or products
    replyTo: {
      id: {
        type: mongoose.Schema.Types.Mixed, // Can be messageId (Number) or productId (ObjectId)
        default: null
      },
      type: {
        type: String,
        enum: ['message', 'product'],
        default: null
      }
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  nextMessageId: {
    type: Number,
    default: 1
  }
}, { timestamps: true });

// Ensure exactly two participants
ConversationSchema.index({ participants: 1 });

ConversationSchema.path('participants').validate(function (value) {
  return value.length === 2;
}, 'A conversation must have exactly two participants.');

module.exports = mongoose.model('Conversation', ConversationSchema);
