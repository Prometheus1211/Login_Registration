const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, 
        required: true,
        unique: true 
      },
password: { type: String, 
        required: true 
      },
files: [{ 
type: String  // Assuming file paths are strings
}],
role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model('User', userSchema);

module.exports = User;
