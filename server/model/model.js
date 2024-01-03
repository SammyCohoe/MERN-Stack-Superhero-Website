const mongoose = require('mongoose');

// mongoose schema for db format
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    type: { type: String },
    flag: { type: String },
    lists: { type: Object },
});

module.exports = mongoose.model('Data', userSchema)