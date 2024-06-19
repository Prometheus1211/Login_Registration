Client Requirement Upload Portal
Overview
The Client Requirement Upload Portal is a web application designed for clients to securely upload their software requirements and associated diagrams. This application utilizes Express.js for the backend, MongoDB for data storage, and Multer for handling file uploads. It also incorporates session management and CSRF protection to ensure secure transactions.

Features
User authentication (login and registration).
Secure file upload (supports PNG format for software diagrams).
Form validation (contact number and email).
CSRF protection for secure form submissions.
Storage of uploaded files in MongoDB using GridFS.
Error handling and feedback for users.
Technologies Used
Backend: Node.js, Express.js, MongoDB, Mongoose, Passport.js, Multer.
Frontend: HTML, CSS, JavaScript (ES6).
Session Management: Express-session, connect-mongo.
Security: csurf for CSRF protection, bcrypt for password hashing.
Prerequisites
Node.js (v14 or higher)
MongoDB (v4 or higher)
Installation
Clone the Repository:

bash
Copy code
git clone https://github.com/yourusername/client-upload-portal.git
cd client-upload-portal
Install Dependencies:

bash
Copy code
npm install
Setup Environment Variables:

Create a .env file in the root directory and add the following variables:

env
Copy code
PORT=3000
MONGO_URI=mongodb://localhost:27017/myapp
SESSION_SECRET=your_secret_key
Replace MONGO_URI with your MongoDB connection string and SESSION_SECRET with a secure secret key.

Database Setup
Ensure that MongoDB is running and accessible at the URI provided in the .env file. You can start MongoDB using:

bash
Copy code
mongod --dbpath /path/to/your/database
Usage
Start the Server:

bash
Copy code
npm start
By default, the server will start at http://localhost:3000.

Access the Portal:

Open your browser and navigate to http://localhost:3000.

User Actions:

Login: Navigate to /login to log in.
Register: Navigate to /register to create a new account.
Upload Requirements: After logging in, navigate to /upload to upload software requirements.