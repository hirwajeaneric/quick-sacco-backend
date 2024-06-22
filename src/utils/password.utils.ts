import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Request } from 'express';
import { UserPayload } from '../dto/auth.dto';
import { SECRET_KEY } from '../config';

declare global {
    namespace Express {
        interface Request {
            user?: UserPayload
        }
    }
};

/**
 * This function generates a salt to be used to generate passwords.
 * @returns salt string
 */
export const GenerateSalt = async (): Promise<string> => {
    return await bcrypt.genSalt();
}

/**
 * 
 * @param password new password
 * @param salt given salt number
 * @returns a password in form of a hashed password.
 */
export const GeneratePassword = async (password: string, salt: string): Promise<string> => {
    return await bcrypt.hash(password, salt);
};

/**
 * 
 * @param enteredPassword the password to be checked
 * @param savedPassword the already existing password from the database
 * @param salt the salt that was used to generate the password
 * @returns true or false if the passwords match.
 */
export const ValidatePassword = async (enteredPassword: string, savedPassword: string, salt: string): Promise<Boolean> => {
    return await GeneratePassword(enteredPassword, salt) === savedPassword;
};

/**
 * Generates a signature token to be used to let a user logged in or do a specific activity once logged in.
 * @param payload an object that contains some information about the logged in user.
 * @returns signature string of text (a jwt token)
 */
export const GenerateToken = async (payload: UserPayload): Promise<string> => {
    return jwt.sign(payload, SECRET_KEY as string, { expiresIn: "1d" }) // Other possible time of expiration formats are: 30m, 1h, 1d,...
};

/**
 * Validates a user signature to determind if a user sending a request is authorized.
 * It recieves the server request and returns a boolean value indicating whether the user is authorized or not.
 * @param req 
 * @returns true | false
 */
export const ValidateToken = async (req: Request): Promise<Boolean> => {
    const signature = req.get('Authorization');
    if (signature) {
        const payload = jwt.verify(signature.split(' ')[1], SECRET_KEY as string) as UserPayload;
        req.user = payload;

        return true;
    }
    return false;
}

interface DecodedPayload extends UserPayload{
    _id: string;
    email: string;
    verified: boolean;
    iat: number;
    exp: number;
}

export const isTokenValid = async (req: Request): Promise<Boolean> => {
    const signature = req.get('Authorization');
    if (signature) {
        const payload = jwt.verify(signature.split(' ')[1], SECRET_KEY as string) as DecodedPayload;
        req.user = payload;
        const now = Date.now() / 1000; // Convert to seconds for consistency

        if (payload.exp < now) {
            return false;
        }

        return true;
    }
    return false;
}

export const ValidateAdmin = async (req: Request): Promise<Boolean> => {
    const signature = req.get('Authorization');
    if (signature) {
        const payload = jwt.verify(signature.split(' ')[1], SECRET_KEY as string) as UserPayload;
        req.user = payload;

        return true;
    }
    return false;
}

export const generateStrongPassword = ():string => {
    const length = 15;
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?";
    let password = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset[randomIndex];
    }
    return password;
}