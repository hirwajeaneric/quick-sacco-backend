import { model, Document, Schema } from "mongoose";

interface UserDoc extends Document {
    firstName: string;
    lastName: string;
    email: string;
    phone: string;
    password: string;
    verified: boolean;
    salt: string;
    role: "Teacher" | "Manager" | "Admin";
    otp: number;
    otpExpiryTime: Date;
    _doc: UserDoc;
};

const UserSchema = new Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    salt: { type: String, required: true },
    verified: { type: Boolean, required: true, default: false },
    otp: { type: Number, required: true,},
    otpExpiryTime: { type: Date, required: true,},
    role: { 
        type: String,
        required: true,
        enum: {
            values: ['Teacher', 'Manager' ,'Admin'],
            message: "Value not allowed as role"
        },
        default: 'Teacher'
    },
    accountStatus: {
        type: String,
        required: true,
        enum: {
            values: ['Active', 'Inactive'],
            message: "Value not allowed as account status"
        },
        default: 'Active'
    }
},{
    toJSON: {
        transform: (doc, ret) => {
            ret.id = ret._id;
            delete ret.password;
            delete ret.salt;
            delete ret.__v;
        }
    },
    timestamps: true
});

const User = model<UserDoc>("User", UserSchema);
export default User;
