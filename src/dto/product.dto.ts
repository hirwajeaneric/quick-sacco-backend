export interface ProductDoc extends Document {
    name: string;
    description: string;
    quantity: number;
    seller: string;
    client: string;
    sellerPhone: string;
    sellerName: string;
    unitPrice: number;
    deliveryTime: number;
    deliveryPrice: number;
    addressLine1: string;
    addressLine2: string;
    paid: boolean;
    verified: boolean;
    imageFiles: string[];
    type: ['Home Appliance'| 'Clothing' | 'Shoes' | 'Furniture' | 'Electronics' | 'Phone' | 'Computer' | 'Part of house' | 'Cereals' | 'Other food items'];
    category: 'Renewable' | 'Non-renewable';
};