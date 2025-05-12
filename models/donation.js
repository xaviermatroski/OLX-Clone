const mongoose = require('mongoose');

const DonationsSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true 
  },
  description: String,
  images: [{
    data: Buffer,
    contentType: String
  }],
  donatedBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  collectedBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: false 
  },
  donationDate: { 
    type: Date, 
    default: Date.now 
  },
  status: {
    type: String,
    enum: ['available', 'collected'],
    default: 'available'
  }
}, { timestamps: true });

module.exports = mongoose.model('Donations', DonationsSchema);