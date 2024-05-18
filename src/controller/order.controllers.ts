import { Request, Response, NextFunction } from "express";
import asyncWrapper from "../middlewares/AsyncWrapper";
import { Order as OrderModel } from "../model/order.model";
import { ValidateToken } from "../utils/password.utils";
import { Product as ProductModel } from "../model/product.model";


export const testRequest = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.body);
    next();
});

export const addNew = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    };

    const existingOrder = await OrderModel.findOne({ client: req.body.client });

    if (existingOrder && existingOrder.paid === false) {
        const product = await ProductModel.findById(req.body.products[0].id);
        existingOrder.products.forEach((p) => {
            if (p.id.toString() === req.body.products[0].id) {
                if (p.quantity === product?.quantity) {
                    return res.status(400).json({ message: "Product quantity limit achieved" });
                } else {
                    p.quantity++;
                    let totalPrice = 0;
                    existingOrder.products.forEach(prod => {
                        totalPrice = totalPrice + (prod.pricePerUnit * prod.quantity) + req.body.deliveryPrice;
                    });
                    existingOrder.totalPrice = totalPrice;
                }
            } else {
                return res.status(400).json({ message: "You already have a product in the cart, please pay the first product and try again." });
            }
        });
        const updatedOrder = await existingOrder.save();
        if (updatedOrder) {
            res.status(201).json({ message: "Cart updated successfully", order: updatedOrder });
        };
    } else {
        req.body.totalPrice = req.body.products[0].quantity * req.body.products[0].pricePerUnit + req.body.deliveryPrice;
        const newOrder = await OrderModel.create(req.body);
        if (newOrder) {
            res.status(201).json({ message: "Order added successfully", order: newOrder });
        };
    }
});


export const list = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    const orders = await OrderModel.find({});
    res.status(200).json({ orders });
});


export const update = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.query; // Assuming order ID comes from the request URL

    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    const orderToUpdate = await OrderModel.findById(id);

    if (!orderToUpdate) {
        return res.status(404).json({ message: "Order not found" });
    }

    // Save the updated order
    const updatedOrder = await OrderModel.findByIdAndUpdate(id, req.body, { new: true });

    if (updatedOrder) {
        if (req.body.paid) {
            var newQuantity = updatedOrder.products[0].maxQuantity - updatedOrder.products[0].quantity;
            if (newQuantity > 0) {
                await ProductModel.findByIdAndUpdate(
                    updatedOrder.products[0].id,
                    {
                        quantity: newQuantity
                    }
                );
            } else {
                await ProductModel.findByIdAndDelete(updatedOrder.products[0].id);
            }
        }

        res.status(200).json({ message: "Order updated successfully", order: updatedOrder });
    } else {
        res.status(500).json({ message: "Error updating order" });
    }
});

export const deleteOrder = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.query; // Assuming order ID comes from the request URL

    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    const deletedOrder = await OrderModel.findByIdAndDelete(id);

    if (!deletedOrder) {
        return res.status(404).json({ message: "Order not found" });
    }

    if (deletedOrder) {
        res.status(200).json({ message: "Order deleted" });
    } else {
        res.status(500).json({ message: "Error deleting order" });
    }
});

export const manageOrderProducts = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.query; // Assuming order ID comes from the request URL

    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    const existingOrder = await OrderModel.findById(id);

    if (existingOrder) {
        const products = existingOrder.products;

        var indexOfProduct = 0;
        products?.forEach((productInOrder, index) => {
            if (productInOrder.id.toString() === req.body.id) {
                console.log(index);
                indexOfProduct = index;
            }
        });

        existingOrder.products[indexOfProduct] = req.body;

        const updatedOrder = await existingOrder.save();

        console.log(updatedOrder);

        if (!updatedOrder) {
            return res.status(404).json({ message: "Adding/removing to cart failed, Order not found" });
        }

        if (updatedOrder) {
            res.status(200).json({ message: "Cart updated successfully", order: updatedOrder });
        } else {
            res.status(500).json({ message: "Error adding order to cart" });
        }
    }
});

export const getClientOrder = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Validate token
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    // Find orders where seller matches the user ID
    const orders = await OrderModel.find({});
    const userOrder = orders.find(order => order.client.toString() === req.user?._id && !order.paid);
    res.status(200).json({ order: userOrder });
});

export const getAllClientOrders = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Validate token
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    // Find orders where seller matches the user ID
    const orders = await OrderModel.find({});
    const userOrders = orders.filter(order => order.client.toString() === req.user?._id && order.paid);
    res.status(200).json({ orders: userOrders });
});

export const getSellerOrders = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    // Validate token
    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }

    // Get user ID from the request (e.g., from req.user)
    const userId = req.user?._id;

    // Find orders where seller matches the user ID
    const userOrders = await OrderModel.find({ seller: userId })
    .populate({
        path: "client",
        model: "User"
    });

    res.status(200).json({ orders: userOrders });
});


export const getOrderById = asyncWrapper(async (req: Request, res: Response, next: NextFunction) => {
    const { id } = req.query; // Assuming order ID comes from the request URL

    const isTokenValid = await ValidateToken(req);
    if (!isTokenValid) {
        return res.status(400).json({ message: "Access denied" });
    }
    // Find the order by ID
    const order = await OrderModel.findById(id);

    if (order) {
        res.status(200).json({ order });
    } else {
        res.status(404).json({ message: "Order not found" });
    }
});
