import { model, Document, Schema } from "mongoose";
import { ProductDoc } from "../dto/product.dto";

const ProductSchema = new Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    quantity: { type: Number, required: true },
    seller: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    client: { type: Schema.Types.ObjectId, ref: 'User', required: false },
    unitPrice: { type: Number, required: true },
    deliveryTime: { type: Number, required: true },
    deliveryPrice: { type: Number, required: true },
    sellerPhone: { type: String, required: true },
    sellerName: { type: String, required: true },
    addressLine1: { type: String, required: true },
    addressLine2: { type: String, required: true },
    verified: { type: Boolean, required: true, default: false },
    imageFiles: { type: [String], required: true },
    paid: { type: Boolean, required: true, default: false },
    deliveryStatus: {
        client: { 
            type: String,
            required: true,
            enum: {
                values: ['Pending', 'Recieved'],
                message: "Invalid delivery status"
            },
            default: 'Pending'
        },
        seller: { 
            type: String,
            required: true,
            enum: {
                values: ['Pending', 'Delivered'],
                message: "Invalid delivery status"
            },
            default: 'Pending'
        },
    },
    type: {
        type: String,
        required: true,
        enum: {
            values: ['Home Appliance', 'Clothing', 'Shoes', 'Furniture', 'Electronics', 'Phone', 'Computer', 'Part of house', 'Cereals', 'Other food items'],
            message: "Invalid product type"
        },
        default: 'Home Appliance'
    },
    category: {
        type: String,
        required: true,
        enum: {
            values: ['Renewable', 'Non-renewable'],
            message: "Invalid product category"
        },
        default: 'Renewable'
    }
},{
    toJSON: {
        transform: (doc, ret) => {
            ret.id = ret._id;
            delete ret.__v;
        }
    },
    timestamps: true
});

export const Product = model<ProductDoc>("Product", ProductSchema);