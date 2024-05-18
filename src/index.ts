import express, { Request, Response } from 'express';
import "dotenv/config";
import { v2 as cloudinary } from 'cloudinary';
import Database  from './services/Database';
import ExpressServer from './services/ExpressServer';

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const StartServer = async () => {
    const app = express();
    await Database();
    await ExpressServer(app);

    app.listen(3000, () => console.log('Server is running on port 3000'));
};

StartServer();