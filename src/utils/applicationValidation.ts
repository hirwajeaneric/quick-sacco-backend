import { Request, Response, NextFunction } from 'express';
import { body, validationResult } from 'express-validator';

const handleValidationErrors = async (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array()[0].msg });
  }
  next();
};

export const validateAddApplication = [
  body('name')
    .not()
    .isEmpty()
    .withMessage('Application name is required')
    .isLength({ min: 3 })
    .withMessage('Application name must be at least 3 characters long'),
  body('description')
    .not()
    .isEmpty()
    .withMessage('Application description is required')
    .isLength({ min: 10 })
    .withMessage('Application description must be at least 10 characters long'),
  body('quantity')
    .isInt() // Assuming quantity is a whole number
    .withMessage('Application quantity must be a valid integer')
    .isInt({ min: 1 })
    .withMessage('Application quantity must be at least 1'),
  body('unitPrice')
    .not()
    .isEmpty()
    .withMessage('Application unit price must provided'),
  body('deliveryPrice')
    .not()
    .isEmpty()
    .withMessage('Delivery price for this application must be provided'),
  body('addressLine1')
    .not()
    .isEmpty()
    .withMessage('Application address line 1 must be provided')
    .isLength({ min: 3 })
    .withMessage('Application address line 1 must be at least 3 characters long'),
  body('addressLine2') // Assuming addressLine2 is required or optional based on your logic
    .optional()
    .isString()
    .withMessage('Application address line 2 must be a string')
    .isLength({ min: 3 })
    .withMessage('Application address line 2 must be at least 3 characters long'),
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
    .withMessage('Invalid application type'),
  body('category')
    .isIn(['Renewable', 'Non-renewable'])
    .withMessage('Invalid application category'),
  handleValidationErrors
];

export const validateUpdateApplication = [
  body('name')
    .not()
    .isEmpty()
    .withMessage('Application name is required')
    .isLength({ min: 3 })
    .withMessage('Application name must be at least 3 characters long'),
  body('description')
    .not()
    .isEmpty()
    .withMessage('Application description is required')
    .isLength({ min: 10 })
    .withMessage('Application description must be at least 10 characters long'),
  body('quantity')
    .isInt() // Assuming quantity is a whole number
    .withMessage('Application quantity must be a valid integer')
    .isInt({ min: 1 })
    .withMessage('Application quantity must be at least 1'),
  body('unitprice')
    .not()
    .isNumeric()
    .withMessage('Application unit price must be a valid number'),
  body('addressLine1')
    .not()
    .isEmpty()
    .withMessage('Application address line 1 must be provided')
    .isLength({ min: 3 })
    .withMessage('Application address line 1 must be at least 3 characters long'),
  body('addressLine2') // Assuming addressLine2 is required or optional based on your logic
    .optional()
    .isString()
    .withMessage('Application address line 2 must be a string')
    .isLength({ min: 3 })
    .withMessage('Application address line 2 must be at least 3 characters long'),
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
    .withMessage('Invalid application type'),
  body('category')
    .isIn(['Renewable', 'Non-renewable'])
    .withMessage('Invalid application category'),
  handleValidationErrors
];

// export const imageValidation = [
//   files('imageFiles')
//     .isArray()
//     .withMessage('Application image files must be an array of strings')
//     .custom((imageFiles) => {
//       if (imageFiles.length === 0) {
//         throw new Error('Application must have at least one image file');
//       }
//       return true;
//     }),
// ];