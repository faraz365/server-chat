import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import { MongoClient, ObjectId } from 'mongodb';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Joi from 'joi';

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// MongoDB connection
const MONGODB_URI = "mongodb+srv://farazabdullah267:SjgRgW3SlAAa05Rl@project.ifut3ay.mongodb.net/";
const JWT_SECRET = "your-secret-key";

let db;

MongoClient.connect(MONGODB_URI)
  .then(client => {
    console.log('Connected to MongoDB');
    db = client.db('chatapp');
  })
  .catch(error => {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  });

// Middleware
app.use(cors());
app.use(express.json());

// Joi validation schemas
const userSignupSchema = Joi.object({
  name: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

const userLoginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const messageSchema = Joi.object({
  content: Joi.string().min(1).max(1000).required(),
  receiverId: Joi.string().required()
});

const updateProfileSchema = Joi.object({
  name: Joi.string().min(2).max(50),
  email: Joi.string().email()
});

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// User Signup
app.post('/api/signup', async (req, res) => {
  try {
    const { error, value } = userSignupSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { name, email, password } = value;

    // Check if user already exists
    const existingUser = await db.collection('users').findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = {
      name,
      email,
      password: hashedPassword,
      createdAt: new Date(),
      isOnline: false
    };

    const result = await db.collection('users').insertOne(user);
    
    // Generate token
    const token = jwt.sign(
      { userId: result.insertedId, email, name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: result.insertedId, name, email }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { error, value } = userLoginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email, password } = value;

    // Find user
    const user = await db.collection('users').findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get all users
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await db.collection('users')
      .find({}, { projection: { password: 0 } })
      .toArray();
    
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update user profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { error, value } = updateProfileSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const userId = new ObjectId(req.user.userId);
    const updateData = { ...value, updatedAt: new Date() };

    const result = await db.collection('users').updateOne(
      { _id: userId },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const updatedUser = await db.collection('users').findOne(
      { _id: userId },
      { projection: { password: 0 } }
    );

    res.json({
      message: 'Profile updated successfully',
      user: updatedUser
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Delete user account
app.delete('/api/account', authenticateToken, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.userId);

    // Delete user's messages
    await db.collection('messages').deleteMany({
      $or: [{ senderId: userId }, { receiverId: userId }]
    });

    // Delete user
    const result = await db.collection('users').deleteOne({ _id: userId });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get messages between users
app.get('/api/messages/:receiverId', authenticateToken, async (req, res) => {
  try {
    const senderId = new ObjectId(req.user.userId);
    const receiverId = new ObjectId(req.params.receiverId);

    const messages = await db.collection('messages')
      .find({
        $or: [
          { senderId, receiverId },
          { senderId: receiverId, receiverId: senderId }
        ]
      })
      .sort({ createdAt: 1 })
      .toArray();

    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Mark messages as read
app.put('/api/messages/mark-read/:senderId', authenticateToken, async (req, res) => {
  try {
    const receiverId = new ObjectId(req.user.userId);
    const senderId = new ObjectId(req.params.senderId);

    const result = await db.collection('messages').updateMany(
      { 
        senderId: senderId,
        receiverId: receiverId,
        isRead: false
      },
      { 
        $set: { 
          isRead: true,
          readAt: new Date()
        }
      }
    );

    res.json({ 
      message: 'Messages marked as read',
      modifiedCount: result.modifiedCount
    });
  } catch (error) {
    console.error('Mark messages as read error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Send message
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { error, value } = messageSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { content, receiverId } = value;
    const senderId = new ObjectId(req.user.userId);
    const receiverObjectId = new ObjectId(receiverId);

    const message = {
      senderId,
      receiverId: receiverObjectId,
      content,
      createdAt: new Date(),
      isRead: false
    };

    const result = await db.collection('messages').insertOne(message);
    
    const savedMessage = await db.collection('messages')
      .findOne({ _id: result.insertedId });

    // Convert ObjectIds to strings for frontend
    const messageForFrontend = {
      ...savedMessage,
      senderId: savedMessage.senderId.toString(),
      receiverId: savedMessage.receiverId.toString()
    };
    // Emit message to receiver via Socket.IO
    io.to(receiverId).emit('newMessage', messageForFrontend);

    res.status(201).json({
      message: 'Message sent successfully',
      data: savedMessage
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Join user to their room
  socket.on('join', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined room`);
  });

  // Handle real-time messaging
  socket.on('sendMessage', async (data) => {
    try {
      const { senderId, receiverId, content } = data;
      
      const message = {
        senderId: new ObjectId(senderId),
        receiverId: new ObjectId(receiverId),
        content,
        createdAt: new Date(),
        isRead: false
      };

      const result = await db.collection('messages').insertOne(message);
      const savedMessage = await db.collection('messages')
        .findOne({ _id: result.insertedId });

      // Convert ObjectIds to strings for frontend
      const messageForFrontend = {
        ...savedMessage,
        senderId: savedMessage.senderId.toString(),
        receiverId: savedMessage.receiverId.toString()
      };

      // Send to receiver
      io.to(receiverId).emit('newMessage', messageForFrontend);
      // Send back to sender for confirmation
      socket.emit('messageSent', messageForFrontend);
    } catch (error) {
      console.error('Socket message error:', error);
      socket.emit('messageError', { error: 'Failed to send message' });
    }
  });

  // Handle marking messages as read
  socket.on('markMessagesAsRead', (data) => {
    const { senderId, receiverId } = data;
    // Notify the sender that their messages have been read
    io.to(senderId).emit('messagesMarkedAsRead', { senderId, receiverId });
  });

  // Handle user status updates
  socket.on('userOnline', async (userId) => {
    try {
      await db.collection('users').updateOne(
        { _id: new ObjectId(userId) },
        { $set: { isOnline: true, lastSeen: new Date() } }
      );
      socket.broadcast.emit('userStatusUpdate', { userId, isOnline: true });
    } catch (error) {
      console.error('User online error:', error);
    }
  });

  socket.on('disconnect', async () => {
    console.log('User disconnected:', socket.id);
    // You might want to update user status to offline here
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});