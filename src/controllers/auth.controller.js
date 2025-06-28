import createHttpError from "http-errors";
import { createUser } from "../services/auth.service.js";
import { generateToken, verifyToken } from "../services/token.service.js";
import { findUser } from "../services/user.service.js";
import jwt from "jsonwebtoken";
import { responseHandler } from "../helpers/responseHandler.js";
import { errorHandler } from "../helpers/errorHandler.js";
import UserModel from "../models/userModel.js";
import bcrypt from "bcrypt";
import crypto from 'crypto'; // or const crypto = require('crypto');
import Token from "../models/token.js"
import { generateNumericToken } from "../utils/generateCode.js";

export const register = async (req, res) => {
    try {
      const { phone } = req.body;
      const new_user = await createUser({ phone, type: 'verify_phone' });
  
      const rawToken = generateNumericToken();
  
      // Hash the token for storage
      const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');
  
      await Token.create({
        userId: new_user._id,
        token: hashedToken,
        type: 'verify_phone',
        expiresAt: new Date(Date.now() + 1000 * 60 * 30), // 30 mins expiry
      });
  
      // Optionally send rawToken to user via SMS/Email
      // Example: sendSMS(phone, `Your verification code: ${rawToken}`)
      console.log(`Your verification code: ${rawToken}`);
  
      const user = {
        _id: new_user._id,
        phone: new_user.phone,
      };
  
      return responseHandler(res, 201, true, "Account Successfully Created", {
        user,
        verificationToken: rawToken, // ⚠️ send only via secure channels
      });
    } catch (error) {
      await errorHandler(error);
      return responseHandler(res, 500, false, "Something went wrong, try again later");
    }
  };


  export const verify_signup = async (req, res) => {
    try {
      const { token, phone } = req.body;
  
      // Hash the token sent by user
      const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  
      // Find token entry
      const storedToken = await Token.findOne({
        token: hashedToken,
        type: 'verify_phone',
        expiresAt: { $gt: Date.now() }, // not expired
      });
  
      if (!storedToken) {
        return responseHandler(res, 400, false, "Invalid or expired token");
      }
  
      // Find and update the user
      const user = await UserModel.findOneAndUpdate(
        { _id: storedToken.userId, phone },
        { is_verified: true },
        { new: true }
      );
  
      if (!user) {
        return responseHandler(res, 404, false, "User not found");
      }
  
      // Optionally delete the token
      await Token.deleteOne({ _id: storedToken._id });
  
      return responseHandler(res, 200, true, "Phone verified successfully", {
        userId: user._id,
        phone: user.phone,
        is_verified: user.is_verified,
      });
    } catch (error) {
      await errorHandler(error);
      return responseHandler(res, 500, false, "Something went wrong");
    }
  };
 
export const login = async (req, res) => {
    try {

        const { email, password } = req.body;
        const user = await UserModel.findOne({ email: email.toLowerCase()}).lean();
        if(!user) return responseHandler(res, 400, false, "Invalid Credentials.", null);
    
        //compare password
        let password_matches = await bcrypt.compare(password, user.password);
        if(!password_matches) return responseHandler(res, 400, false, "Invalid Credentials.", null);

        const access_token = await generateToken(
            { userId: user._id },
            "30d",
            process.env.ACCESS_TOKEN_SECRET);
        
        const refresh_token = await generateToken(
            { userId: user._id },
            "30d",
            process.env.REFRESH_TOKEN_SECRET);
        
        res.cookie('refreshToken', refresh_token, {
            httpOnly: true,
            path: "/api/v1/auth/refreshtoken",
            maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
        });

        const user_data = {
            _id: user._id,
            name: user.name,
            email: user.email,
            picture: user.picture,
            status: user.status,
            token: access_token
        }
        return responseHandler(res, 201, true, `Account Successfully Created.`, user_data)
    } catch (error) {
        await errorHandler(error);
        return responseHandler(res, 500, false, "Something went wrong, try again later");
    }
}

export const logout = async (req, res, next) => {
    try {
        res.clearCookie('refreshToken', { path: "/api/v1/auth/refreshtoken"});
        return responseHandler(res, 200, true, "Logged out", null);

    } catch (error) {
        await errorHandler(error);
        return responseHandler(res, 500, false, "Something went wrong, try again later");
    }
}

export const refreshToken= async (req, res, next) => {
    try {
       const refresh_token = req.cookies.refreshToken;
       if(!refresh_token) return responseHandler(res, 401, false, "Please login.")

       const check = await verifyToken(refresh_token, process.env.REFRESH_TOKEN_SECRET);
       const user = await findUser(check.userId);
    
       const access_token = await generateToken(
        { userId: user._id },
        "1d",
        process.env.ACCESS_TOKEN_SECRET
       );
  
        const user_data = {
            _id: user._id,
            name: user.name,
            email: user.email,
            picture: user.picture,
            status: user.status,
            token: access_token
        }

        return responseHandler(res, 200, true, "Token refresh successful", user_data)
    } catch (error) { 
       await errorHandler(error);
       return responseHandler(res, 500, false, "Something went wrong, try again later");
    }
}

export const getLoginStatus = async (req, res, next) => {
    try {
        const { token } = req.params;
        
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
            if(err){
                return responseHandler(res, 200, true, "User Logged Out", false)
            }else{
                return responseHandler(res, 200, true, "User Logged In", true)
            }  
        })

    } catch (error) {
        await errorHandler(error);
        return responseHandler(res, 500, false, "Something went wrong, try again later");
    }
}

export const changeProfileImage = async (req, res) => {
    try {
        const { picture } = req.body;
        const user_id = req.user.userId;

        const update_photo = await UserModel.findByIdAndUpdate({ _id: user_id}, {
            picture
        });

        update_photo.picture = picture;
       
        return responseHandler(res, 200, true, "Profile Picture Updated", picture);
    } catch (error) {
        await errorHandler(error);
        return responseHandler(res, 500, false, "Something went wrong, try again later.");
    }
}