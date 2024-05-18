import { Request, Response, NextFunction } from 'express';
import { body, validationResult } from 'express-validator';

const handleValidationErrors = async (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array()[0].msg });
  }
  next();
};

export const validateAddProduct = [
  body('name')
    .not()
    .isEmpty()
    .withMessage('Product name is required')
    .isLength({ min: 3 })
    .withMessage('Product name must be at least 3 characters long'),
  body('description')
    .not()
    .isEmpty()
    .withMessage('Product description is required')
    .isLength({ min: 10 })
    .withMessage('Product description must be at least 10 characters long'),
  body('quantity')
    .isInt() // Assuming quantity is a whole number
    .withMessage('Product quantity must be a valid integer')
    .isInt({ min: 1 })
    .withMessage('Product quantity must be at least 1'),
  body('unitPrice')
    .not()
    .isEmpty()
    .withMessage('Product unit price must provided'),
  body('deliveryPrice')
    .not()
    .isEmpty()
    .withMessage('Delivery price for this product must be provided'),
  body('addressLine1')
    .not()
    .isEmpty()
    .withMessage('Product address line 1 must be provided')
    .isLength({ min: 3 })
    .withMessage('Product address line 1 must be at least 3 characters long'),
  body('addressLine2') // Assuming addressLine2 is required or optional based on your logic
    .optional()
    .isString()
    .withMessage('Product address line 2 must be a string')
    .isLength({ min: 3 })
    .withMessage('Product address line 2 must be at least 3 characters long'),
  body('type')
    .isIn([
      'Home Appliance',
      'Clothing',
      'Shoes',
      'Furniture',
      'Electronics',
      'Phone',
      'Computer',
      'Part of house',
      'Cereals',
      'Other food items',
    ])
    .withMessage('Invalid product type'),
  body('category')
    .isIn(['Renewable', 'Non-renewable'])
    .withMessage('Invalid product category'),
  handleValidationErrors
];

export const validateUpdateProduct = [
  body('name')
    .not()
    .isEmpty()
    .withMessage('Product name is required')
    .isLength({ min: 3 })
    .withMessage('Product name must be at least 3 characters long'),
  body('description')
    .not()
    .isEmpty()
    .withMessage('Product description is required')
    .isLength({ min: 10 })
    .withMessage('Product description must be at least 10 characters long'),
  body('quantity')
    .isInt() // Assuming quantity is a whole number
    .withMessage('Product quantity must be a valid integer')
    .isInt({ min: 1 })
    .withMessage('Product quantity must be at least 1'),
  body('unitprice')
    .not()
    .isNumeric()
    .withMessage('Product unit price must be a valid number'),
  body('addressLine1')
    .not()
    .isEmpty()
    .withMessage('Product address line 1 must be provided')
    .isLength({ min: 3 })
    .withMessage('Product address line 1 must be at least 3 characters long'),
  body('addressLine2') // Assuming addressLine2 is required or optional based on your logic
    .optional()
    .isString()
    .withMessage('Product address line 2 must be a string')
    .isLength({ min: 3 })
    .withMessage('Product address line 2 must be at least 3 characters long'),
  body('deliveryStatus.client')
    .isIn(['Pending', 'Received'])
    .withMessage('Invalid delivery status for client'),
  body('deliveryStatus.seller')
    .isIn(['Pending', 'Delivered'])
    .withMessage('Invalid delivery status for seller'),
  body('type')
    .isIn([
      'Home Appliance',
      'Clothing',
      'Shoes',
      'Furniture',
      'Electronics',
      'Phone',
      'Computer',
      'Part of house',
      'Cereals',
      'Other food items',
    ])
    .withMessage('Invalid product type'),
  body('category')
    .isIn(['Renewable', 'Non-renewable'])
    .withMessage('Invalid product category'),
  handleValidationErrors
];

// export const imageValidation = [
//   files('imageFiles')
//     .isArray()
//     .withMessage('Product image files must be an array of strings')
//     .custom((imageFiles) => {
//       if (imageFiles.length === 0) {
//         throw new Error('Product must have at least one image file');
//       }
//       return true;
//     }),
// ];