import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcrypt";

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: false
    },
    phone: {
        type: String,
        required: [true, "Please provide your Phone Number"],
        unique: [true, "Phone Number already used"],
    },
    picture: {
        type: String,
        default: "https://t4.ftcdn.net/jpg/05/49/98/39/360_F_549983970_bRCkYfk0P6PP5fKbMhZMIb07mCJ6esXL.jpg",
    },

    is_verified: {
        type: Boolean,
        default: false
    },

    status: {
        type: String,
        default: ""
    },

    bio: {
        type: String,
        default: 'Hey there! I am using whatsapp',

    }
},{
    collection: "users",
    timestamps: true,
});

const UserModel = mongoose.models.UserModel || mongoose.model('UserModel', userSchema);

export default UserModel;