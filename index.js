// Rewritten index.js using Mongoose instead of native MongoDB driver
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Joi from 'joi';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// MongoDB and JWT setup
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("Connected to MongoDB"))
  .catch(err => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// Mongoose Models
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date,
  isOnline: { type: Boolean, default: false },
  lastSeen: Date
});

const messageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  createdAt: { type: Date, default: Date.now },
  isRead: { type: Boolean, default: false },
  readAt: Date
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

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

const messageJoiSchema = Joi.object({
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
  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/signup', async (req, res) => {
  try {
    const { error, value } = userSignupSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const { name, email, password } = value;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id, email, name }, JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({ message: 'User created', token, user: { id: newUser._id, name, email } });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { error, value } = userLoginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const { email, password } = value;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ message: 'Login successful', token, user: { id: user._id, name: user.name, email: user.email } });
    console.log(token)
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { error, value } = updateProfileSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const updatedUser = await User.findByIdAndUpdate(req.user.userId, { ...value, updatedAt: new Date() }, { new: true, projection: { password: 0 } });
    if (!updatedUser) return res.status(404).json({ message: 'User not found' });

    res.json({ message: 'Profile updated', user: updatedUser });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/api/account', authenticateToken, async (req, res) => {
  try {
    await Message.deleteMany({ $or: [{ senderId: req.user.userId }, { receiverId: req.user.userId }] });
    const result = await User.deleteOne({ _id: req.user.userId });
    if (result.deletedCount === 0) return res.status(404).json({ message: 'User not found' });

    res.json({ message: 'Account deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/messages/:receiverId', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { senderId: req.user.userId, receiverId: req.params.receiverId },
        { senderId: req.params.receiverId, receiverId: req.user.userId }
      ]
    }).sort({ createdAt: 1 });

    res.json(messages);
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});


app.get('/', (req, res) => {
  res.send('Server is running successfully with mongodb');
});


app.put('/api/messages/mark-read/:senderId', authenticateToken, async (req, res) => {
  try {
    const result = await Message.updateMany({
      senderId: req.params.senderId,
      receiverId: req.user.userId,
      isRead: false
    }, {
      $set: { isRead: true, readAt: new Date() }
    });

    res.json({ message: 'Messages marked as read', modifiedCount: result.modifiedCount });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { error, value } = messageJoiSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const message = new Message({
      senderId: req.user.userId,
      receiverId: value.receiverId,
      content: value.content
    });
    await message.save();

    const msg = message.toObject();
    msg.senderId = msg.senderId.toString();
    msg.receiverId = msg.receiverId.toString();

    // io.to(value.receiverId).emit('newMessage', msg);
    // res.status(201).json({ message: 'Message sent', data: msg });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Socket.IO Events
// io.on('connection', (socket) => {
//   console.log('User connected:', socket.id);

//   socket.on('join', (userId) => {
//     socket.join(userId);
//     console.log(`User ${userId} joined room`);
//   });

//   socket.on('sendMessage', async (data) => {
//     try {
//       const message = new Message({
//         senderId: data.senderId,
//         receiverId: data.receiverId,
//         content: data.content
//       });
//       await message.save();

//       const msg = message.toObject();
//       msg.senderId = msg.senderId.toString();
//       msg.receiverId = msg.receiverId.toString();

//       io.to(data.receiverId).emit('newMessage', msg);
//       socket.emit('messageSent', msg);
//     } catch (err) {
//       console.error('Socket message error:', err);
//       socket.emit('messageError', { error: 'Failed to send message' });
//     }
//   });

//   socket.on('markMessagesAsRead', ({ senderId, receiverId }) => {
//     io.to(senderId).emit('messagesMarkedAsRead', { senderId, receiverId });
//   });

//   socket.on('userOnline', async (userId) => {
//     try {
//       await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() });
//       socket.broadcast.emit('userStatusUpdate', { userId, isOnline: true });
//     } catch (err) {
//       console.error('User online error:', err);
//     }
//   });

//   socket.on('disconnect', () => {
//     console.log('User disconnected:', socket.id);
//   });
// });

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
