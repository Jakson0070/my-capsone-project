const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = 3000;
const JWT_SECRET = "your_jwt_secret";
const MONGO_URI = "mongodb://localhost:27017/taskApp";

// Middleware
app.use(cors({ origin: "*" }));
app.use(express.json());
app.use(express.static("public"));

// connect to the database
mongoose
  .connect("mongodb+srv://riju:admin@cluster0.09ehr.mongodb.net/crud", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

const taskSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, required: true },
  description: String,
  deadline: Date,
  priority: {
    type: String,
    enum: ["low", "medium", "high"],
    default: "medium",
  },
  completed: { type: Boolean, default: false },
});

const Task = mongoose.model("Task", taskSchema);

// Register API
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Username and Password are required");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(400).json({ error: "Username already exists" });
  }
});

// Login API
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ token, message: "Login successful" });
});

// Protected User Info Route
app.get("/api/userinfo", async (req, res) => {
  const token = req.headers["authorization"];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select("-password");
    res.json(user);
  } catch (err) {
    res.status(401).json({ error: "Unauthorized" });
  }
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Unauthorized" });
    req.userId = decoded.userId;
    next();
  });
};

// Create a Task
app.post("/api/tasks", verifyToken, async (req, res) => {
  const { title, description, deadline, priority } = req.body;
  try {
    const newTask = new Task({
      userId: req.userId,
      title,
      description,
      deadline,
      priority,
    });
    await newTask.save();
    res.status(201).json(newTask);
  } catch (err) {
    res.status(400).json({ error: "Failed to create task" });
  }
});

// Get All Tasks with Search Functionality
app.get("/api/tasks", verifyToken, async (req, res) => {
  const { search } = req.query;
  const query = {
    userId: req.userId,
    ...(search && {
      $or: [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ],
    }),
  };

  try {
    const tasks = await Task.find(query);
    res.json(tasks);
  } catch (err) {
    res.status(400).json({ error: "Failed to fetch tasks" });
  }
});

// Update a Task
app.put("/api/tasks/:id", verifyToken, async (req, res) => {
  const { title, description, deadline, priority, completed } = req.body;
  try {
    const updatedTask = await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { title, description, deadline, priority, completed },
      { new: true }
    );
    res.json(updatedTask);
  } catch (err) {
    res.status(400).json({ error: "Failed to update task" });
  }
});

// Delete a Task
app.delete("/api/tasks/:id", verifyToken, async (req, res) => {
  try {
    await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    res.json({ message: "Task deleted successfully" });
  } catch (err) {
    res.status(400).json({ error: "Failed to delete task" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
