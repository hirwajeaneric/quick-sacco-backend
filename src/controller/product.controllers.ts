import { Request, Response, NextFunction } from "express";
import asyncWrapper from "../middlewares/AsyncWrapper";
import { Product as ProductModel } from "../model/product.model";
import { ValidateToken } from "../utils/password.utils";
import { ProductDoc } from "../dto/product.dto";

export const addNew = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    };

    req.body.seller = req.user?._id;

    if (req.files) {
        req.body.imageFiles = [];
        const files = req.files as [Express.Multer.File]
        const images = files.map((file: Express.Multer.File) => file.filename);
        images.forEach((image) => {
            req.body.imageFiles.push(image);
        });
    };

    const newProduct = await ProductModel.create(req.body);

    if (newProduct) {
        res.status(201).json({ message: "Product added successfully", product: newProduct });
    };
});



export const list = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const products = await ProductModel.find({});
    res.status(200).json({ products });
});

/**
 * Updates a product by its ID.
 *
 * @param req - The Express.js request object.
 * @param res - The Express.js response object.
 * @param next - The Express.js next middleware function.
 * @returns - A JSON response with the updated product or an error message.
 */
export const update = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.query; // Assuming product ID comes from the request URL
    // console.log(req.query);

    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    const productToUpdate = await ProductModel.findById(id);

    if (!productToUpdate) {
        return res.status(404).json({ message: "Product not found" });
    }

    if (req.files) {
        req.body.imageFiles = [];
        const files = req.files as [Express.Multer.File]
        const images = files.map((file: Express.Multer.File) => file.filename);
        images.forEach((image) => {
            req.body.imageFiles.push(image);
        });
    };

    // Save the updated product
    const updatedProduct = await ProductModel.findByIdAndUpdate(id, req.body, { new: true });

    if (updatedProduct) {
        res.status(200).json({ message: "Product updated successfully", product: updatedProduct });
    } else {
        res.status(500).json({ message: "Error updating product" });
    }
});

export const getUserProducts = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Validate token
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    // Get user ID from the request (e.g., from req.user)
    const userId = req.user?._id;

    // Find products where seller matches the user ID
    const userProducts = await ProductModel.find({ seller: userId });

    res.status(200).json({ products: userProducts });
});


export const getProductById = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.query; // Assuming product ID comes from the request URL

    // Find the product by ID
    const product = await ProductModel.findById(id);

    if (product) {
        res.status(200).json({ product });
    } else {
        res.status(404).json({ message: "Product not found" });
    }
});


export const getAllAvailableProducts = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Filter products where `client` field is null
    const products = await ProductModel.find({});
    const availableProducts = products.filter((product: ProductDoc) => product.paid === false);

    res.status(200).json({ products: availableProducts });
});

export const getBoughtProducts = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Validate token
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    // Get user ID from the request (e.g., from req.user)
    const userId = req.user?._id;

    // Find products where `client` matches the user ID
    const boughtProducts = await ProductModel.find({ client: userId });

    res.status(200).json({ products: boughtProducts });
});

export const deleteProduct = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Validate token (assuming authorization is required for deletion)
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    const { id } = req.query;

    // Find the product to delete
    const productToDelete = await ProductModel.findById(id);

    if (!productToDelete) {
        return res.status(404).json({ message: "Product not found" });
    }

    // Delete the product
    await productToDelete.deleteOne();

    res.status(200).json({ message: "Product deleted successfully" });
});