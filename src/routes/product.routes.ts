import express from "express";
import multer from 'multer';
import { addNew, deleteProduct, getAllAvailableProducts, getBoughtProducts, getProductById, getUserProducts, list, update } from "../controller/product.controllers";
import { validateAddProduct } from "../utils/productValidation";

const productRouter = express.Router();

const imageStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './src/images');
    },
    filename: (req, file, cb) => {
        cb(null, new Date().toISOString() + '_' + file.originalname);
    }
});

const images = multer({ storage: imageStorage }).array('imageFiles', 5);

productRouter.post('/add',images, validateAddProduct, addNew);
productRouter.get('/list', list);
productRouter.put('/update', images, update);
productRouter.get('/user', getUserProducts);
productRouter.get('/findById', getProductById);
productRouter.get('/available', getAllAvailableProducts);
productRouter.get('/baught', getBoughtProducts);
productRouter.delete('/delete', deleteProduct);

export default productRouter;