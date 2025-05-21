# trash_market_backend
A system that helps individuals to buy and sell trash on a shared market which is also controlled by RURA to get data on environment and kinds of trash people dum on a daily basis to leverage that in decision making a planning for the future.

## Environment Variables
```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration
MONGODB_CONNECTION_STRING=mongodb://localhost:27017/quick-sacco

# JWT Configuration
SECRET_KEY=your-secret-key-here

# Email Configuration
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-email-app-password

# Client URLs (CORS Configuration)
CLIENT_URL=http://localhost:5173
CLIENT_URL_1=http://localhost:3000

# Cloudinary Configuration (if needed)
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
```
