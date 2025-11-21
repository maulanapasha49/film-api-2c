const mongoose = require('mongoose');

const directorSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    birthYear: { type: Number, required: true }
}, { timestamps: true });

const Director = mongoose.model('Director', directorSchema);

module.exports = Director;