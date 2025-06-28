import mongoose, { mongo } from "mongoose";
const { ObjectId } = mongoose.Schema.Types;

const tokenSchema = mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User',
    },

    token: {
        type: String,
        required: true,
    },

    type: {
        type: String,
        enum: ['verify_phone', 'reset_password', 'refresh_token'],
        default: 'verify_phone',
    },

    expiresAt: {
        type: Date,
        required: true,
    },

    createdAt: {
        type: Date,
        default: Date.now,
    },

    blacklistd: {
        type: Boolean,
        default: false,
    }
});

const TokenModel = mongoose.models.Token || mongoose.model("TokenModel", tokenSchema);

export default TokenModel;