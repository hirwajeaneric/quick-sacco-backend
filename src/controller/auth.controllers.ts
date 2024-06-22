import { Request, Response, NextFunction } from "express";
import asyncWrapper from "../middlewares/AsyncWrapper";
import UserModel from "../model/user.model";
import { GeneratePassword, GenerateSalt, GenerateToken, ValidatePassword, ValidateToken, generateStrongPassword, isTokenValid } from "../utils/password.utils";
import { GenerateOTP, sendEmail } from "../utils/notification.utils";
import { Token } from "../model/token.model";

export const generateManagerPassword = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.role === 'Manager') {
        req.body.password = generateStrongPassword();
        req.body.verified = true;
    }
    next();
});

export const signUp = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Check existing email
    const existingUser = await UserModel.findOne({ email: req.body.email });
    if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
    };

    let userPassword = req.body.password;

    const salt = await GenerateSalt();
    req.body.password = await GeneratePassword(req.body.password, salt);

    // Create OTP
    const { otp, expiryDate } = GenerateOTP();
    req.body.otp = otp;
    req.body.salt = salt;
    req.body.otpExpiryTime = expiryDate;
    
    // Record account
    const recordedUser = await UserModel.create(req.body);
    
    var emailMessageBody = '';
    if (recordedUser.role === 'Manager') {
        emailMessageBody = `Hello ${recordedUser.lastName},\n\nHere are your account credentials. \n\nEmail: ${recordedUser.email}\nPassword: ${userPassword}\n\nClick on the link bellow to login to your account: \n${process.env.CLIENT_URL}/manager/auth/signin.\n\nBest regards,\n\nQuick SACCO`;
    } else if (recordedUser.role === 'Admin') {
        emailMessageBody = `Hello ${recordedUser.lastName},\n\nYour OTP is ${otp}. \n\nClick on the link bellow to validate your account: \n${process.env.CLIENT_URL}/admin/auth/verifyotp?id=${recordedUser._id}.\n\nBest regards,\n\nQuick SACCO`;
    } else {
        emailMessageBody = `Hello ${recordedUser.lastName},\n\nYour OTP is ${otp}. \n\nClick on the link bellow to validate your account: \n${process.env.CLIENT_URL}/verifyotp?id=${recordedUser._id}.\n\nBest regards,\n\nQuick SACCO`;
    }

    // Send email
    if (recordedUser) {
        await sendEmail(req.body.email, "Verify your account", emailMessageBody);
    }
    // Send response
    res.status(200).json({ message: "Account created!" });
});

export const signIn = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Check existing email
    const existingUser = await UserModel.findOne({ email: req.body.email });
    if (!existingUser) {
        return res.status(400).json({ message: "Invalid email or password" });
    };

    // Check password
    const isPasswordValid = await ValidatePassword(req.body.password, existingUser.password, existingUser.salt);
    if (!isPasswordValid) {
        return res.status(400).json({ message: "Invalid email or password" });
    };

    if (!existingUser.verified) {
        return res.status(400).json({ message: "Please verify your account first" });
    }

    const token = await GenerateToken({
        _id: existingUser._id,
        email: existingUser.email,
        verified: existingUser.verified
    });

    const { password: hashedPassword, salt,otp, otpExpiryTime,verified, ...rest } = existingUser._doc;

    // Send response
    res
        .cookie("access-token", token, { httpOnly: true, expires: new Date(Date.now() + 3600000) })
        .status(200)
        .json({ message: "Sign in successful", user: rest, token });
});

export const getUserProfile = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const authToken = req.get('Authorization');
    
    if (!authToken?.split(' ')[1]) {
        return res.status(401).json({ message: "Access denied!" });
    }
    
    const isValid = await isTokenValid(req);
    if (!isValid) {
        return res.status(401).json({ message: "Access denied!" });
    }

    const existingUser = await UserModel.findOne({ email: req.user?.email });

    if (!existingUser) {
        return res.status(400).json({ message: "User not found" });
    }
    
    const token = await GenerateToken({
        _id: existingUser._id,
        email: existingUser.email,
        verified: existingUser.verified
    });

    const { password: hashedPassword, salt,otp, otpExpiryTime,verified, ...rest } = existingUser._doc;

    // Send response
    res
        .cookie("access-token", token, { httpOnly: true, expires: new Date(Date.now() + 3600000) })
        .status(200)
        .json(rest);
});

export const getManagers = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const authToken = req.get('Authorization');
    
    if (!authToken?.split(' ')[1]) {
        return res.status(401).json({ message: "Access denied!" });
    }
    
    const isValid = await isTokenValid(req);
    if (!isValid) {
        return res.status(401).json({ message: "Access denied!" });
    }

    const managers = await UserModel.find({ role: 'Manager' });

    if (!managers) {
        return res.status(400).json({ message: "No managers found" });
    }
    
    // Send response
    res.status(200).json({ managers });
});

export const getTeachers = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const authToken = req.get('Authorization');
    
    if (!authToken?.split(' ')[1]) {
        return res.status(401).json({ message: "Access denied!" });
    }
    
    const isValid = await isTokenValid(req);
    if (!isValid) {
        return res.status(401).json({ message: "Access denied!" });
    }

    const teachers = await UserModel.find({ role: 'Teacher' });

    if (!teachers) {
        return res.status(400).json({ message: "No teachers found" });
    }
    
    // Send response
    res.status(200).json({ teachers });
});


export const regenerateOTP = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const foundUser = await UserModel.findById(req.body.id);
    if (!foundUser) {
        return res.status(400).json({ message: "Account with this email is not registered!" });
    };

    // Generate new OTP
    const { otp, expiryDate } = GenerateOTP();

    // Update user info
    foundUser.otp = otp;
    foundUser.otpExpiryTime = expiryDate;
    await foundUser.save();

    // Send email
    await sendEmail(foundUser.email, "Verify your account", `Hello ${foundUser.lastName},\n\nYour OTP is ${otp}. \n\nClick on the link bellow to validate your account: \n${process.env.CLIENT_URL}/verifyotp?id=${foundUser._id}\n\nBest regards,\n\nQuickSacco`);
    
    // Send response
    res.status(200).json({ message: "OTP resent!" });
});


export const verifyOTP = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.body);
    const foundUser = await UserModel.findOne({ otp: req.body.otp });
    
    if (!foundUser) {
        return res.status(400).json({ message: "Invalid OTP" });
    };

    if (new Date(foundUser.otpExpiryTime).getTime() < new Date().getTime()) {
        return res.status(400).json({ message: "OTP expired" });
    };

    foundUser.verified = true;
    const savedUser = await foundUser.save();

    if (savedUser) {
        return res.status(200).json({ message: "User account verified!" });
    }
});


export const forgotPassword = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const foundUser = await UserModel.findOne({ email: req.body.email });
    if (!foundUser) {
        return res.status(400).json({ message: "Account with this email is not registered!" });
    };

    const token = await GenerateToken({
        _id: foundUser._id,
        email: foundUser.email,
        verified: foundUser.verified
    });

    await Token.create({
        token,
        user: foundUser._id,
        expirationDate: new Date().getTime() + (60 * 1000 * 5),
    });
    
    let link = '';
    if (foundUser.role === "Teacher") {
        link = `${process.env.CLIENT_URL}/resetpassword?token=${token}&id=${foundUser._id}`
    } else if (foundUser.role === "Manager") {
        link = `${process.env.CLIENT_URL}/manager/auth/resetpassword?token=${token}&id=${foundUser._id}`
    } else {
        link = `${process.env.CLIENT_URL}/admin/auth/resetpassword?token=${token}&id=${foundUser._id}`
    }

    const emailBody = `Hello ${foundUser.lastName},\n\nClick on the link bellow to reset your password.\n\n${link}\n\nBest regards,\n\nQuickSacco`;

    await sendEmail(foundUser.email, "Reset your password", emailBody);

    res.status(200).json({ message: "We sent you a reset password link on your email!" });
});


export const resetPassword = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Invalid or expired token" });
    };

    const foundUser = await UserModel.findById(req.user?._id);
    if (!foundUser) {
        return res.status(400).json({ message: "Invalid or expired token" });
    };

    foundUser.password = await GeneratePassword(req.body.password, foundUser.salt);

    await foundUser.save()
    await Token.deleteOne({ user: req.user?._id });

    res.status(200).json({ message: "Your password has been reset!" });
});


export const updateAccount = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    };

    await UserModel.findByIdAndUpdate(req.user?._id, {
        $set: {
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            phone: req.body.phone,
            code: req.body.code,
            addressLine1: req.body.addressLine1,
            addressLine2: req.body.addressLine2,
            city: req.body.city,
        },
        new: true
    });
    
    const updatedUser = await UserModel.findById(req.user?._id);
    
    if (!updatedUser) {
        return res.status(400).json({ message: "User not found" });
    };

    res.status(200).json({ message: "Account info updated successfully!", user: updatedUser });
});

export const verifyToken = asyncWrapper(async(req: Request, res: Response, next: NextFunction) => {
    const validToken = await isTokenValid(req);

    if (!validToken) {
        return res.status(400).json({ message: "Access denied" });
    } 
    res.status(200).json({ message: "Token is valid" });
});