import { Schema } from "mongoose";

type DeliveryStatus = {
    client: "Pending" | "Recieved";
    seller: "Pending" | "Delivered";
}

export type ProductTypes = {
    id: Schema.Types.ObjectId;
    name: string;
    image: string;
    quantity: number;
    maxQuantity: number;
    pricePerUnit: number;
}

export interface OrderDoc extends Document {
    client: Schema.Types.ObjectId;
    seller: Schema.Types.ObjectId;
    deliveryPrice: Number;
    deliveryTime: Number;
    addressLine1: String,
    addressLine2?: String,
    products: ProductTypes[];
    totalPrice: Number;
    paid: boolean;
    status: ['Pending' | 'In Progress' | 'Completed'];
    deliveryStatus: DeliveryStatus;
};