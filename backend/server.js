const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
require("dotenv").config();
// const { verifyToken } = require("./middleware/auth"); // ❌ REMOVED: Since verifyToken is defined below
const app = express();

// --- General Middleware ---
app.use(express.json());
app.use(cors({
  origin: ["http://localhost:3000", "http://127.0.0.1:3000"],
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
  credentials: true,
  allowedHeaders: "Content-Type,Authorization",
}));

// ✅ Serve uploaded files (e.g. profile photos, trip images)
app.use("/uploads", express.static("uploads"));

// --- Custom Middleware ---

// ✅ Middleware to verify JWT token (Kept this single definition)
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  
  if (!authHeader) return res.status(401).json({ message: "No token provided" });

  // Token is typically sent as "Bearer <token>"
  const token = authHeader.split(" ")[1]; 
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      // 403 Forbidden - Token exists but is invalid/expired
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    // Store decoded payload (user id, email) in req.user
    req.user = decoded; 
    next();
  });
}

// ✅ Configure Multer storage for all uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// --- MySQL Connection ---
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
    return;
  }
  console.log("✅ Connected to MySQL Database!");
});

// --- Test Route ---
app.get("/", (req, res) => {
  res.json({ message: "Backend connected!" });
});


// ============================
// 🔹 AUTH ROUTES (UNPROTECTED)
// ============================

// ✅ SIGNUP
app.post("/signup", async (req, res) => {
  const { name, email, password, gender, phone } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ message: "All fields are required" });

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).json({ message: "Server error" });

    if (result.length > 0)
      return res.status(400).json({ message: "User already exists" });

    try {
      const hashed = await bcrypt.hash(password, 10);
      db.query(
        "INSERT INTO users (name, email, password, gender, phone) VALUES (?, ?, ?, ?, ?)",
        [name, email, hashed, gender || null, phone || null],
        (err2) => {
          if (err2) {
            console.error(err2);
            return res.status(500).json({ message: "Error creating user" });
          }
          res.json({ message: "Signup successful!" });
        }
      );
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: "Error during signup" });
    }
  });
});

// ✅ LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "All fields are required" });

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
    if (err) return res.status(500).json({ message: "Server error" });
    if (result.length === 0)
      return res.status(400).json({ message: "User not found" });

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful!",
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  });
});


// ============================
// 🔹 TRIP ROUTES (PROTECTED)
// ============================

// ✅ PROTECTED: Add a trip for the logged-in user
app.post("/api/trips", verifyToken, upload.array("images", 10), (req, res) => {
  const userId = req.user.id; // <-- user ID from token
  const {
    destination,
    country,
    startDate,
    endDate,
    travelType,
    travelers,
    stayCost,
    transportCost,
    foodCost,
    shoppingCost,
    otherCost,
    notes,
  } = req.body;

  const imagePaths = req.files ? req.files.map((f) => `/uploads/${f.filename}`) : [];

  const totalExpense =
    Number(stayCost || 0) +
    Number(transportCost || 0) +
    Number(foodCost || 0) +
    Number(shoppingCost || 0) +
    Number(otherCost || 0);

  const sql = `
    INSERT INTO trips (
      user_id, destination, country, start_date, end_date,
      travel_type, travelers, stay_cost, transport_cost,
      food_cost, shopping_cost, other_cost, total_expense,
      notes, images
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [
      userId,
      destination,
      country,
      startDate,
      endDate,
      travelType,
      travelers,
      stayCost,
      transportCost,
      foodCost,
      shoppingCost,
      otherCost,
      totalExpense,
      notes,
      imagePaths.join(","),
    ],
    (err) => {
      if (err) {
        console.error("❌ Error adding trip:", err);
        return res.status(500).json({ message: "Failed to add trip" });
      }
      res.json({ message: "Trip added successfully!" });
    }
  );
});

// ✅ PROTECTED: Fetch all trips belonging to logged-in user (consolidated)
app.get("/api/trips", verifyToken, (req, res) => {
  const userId = req.user.id; // pulled from token
  
  // Select all trip fields belonging to the user
  const sql = `
    SELECT * FROM trips 
    WHERE user_id = ? 
    ORDER BY start_date DESC
  `;

  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("❌ Error fetching trips:", err);
      return res.status(500).json({ message: "Error fetching trips" });
    }
    res.json(results);
  });
});


// ============================
// 🔹 PROFILE ROUTES (PROTECTED)
// ============================

// ✅ PROTECTED: Fetch current user profile (consolidated & secure)
app.get("/api/profile", verifyToken, (req, res) => {
  const userId = req.user.id; // pulled directly from verified token

  db.query(
    "SELECT id, name, email, gender, phone, profile_photo FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      if (err) {
        console.error("❌ Error fetching profile:", err);
        return res.status(500).json({ message: "Server error" });
      }

      if (results.length === 0)
        return res.status(404).json({ message: "User not found" });

      const user = results[0];

      // ✅ Ensure correct image URL is sent back (if one exists)
      if (user.profile_photo) {
        // Construct the full URL, checking if it already has a protocol/domain
        const photoPath = user.profile_photo.startsWith("/") 
            ? user.profile_photo 
            : `/uploads/${user.profile_photo.replace('/uploads/', '')}`;
            
        user.profile_photo = `http://localhost:5050${photoPath}`;
      } else {
        user.profile_photo = "http://localhost:5050/uploads/default.png";
      }

      res.json(user);
    }
  );
});


// ✅ PROTECTED: Update User Profile (consolidated & secure)
app.put("/api/profile", verifyToken, upload.single("profile_photo"), (req, res) => {
  const userId = req.user.id;
  const { name, gender, phone } = req.body;
  const newPhotoPath = req.file ? `/uploads/${req.file.filename}` : null;

  let sql = `
    UPDATE users 
    SET name = ?, gender = ?, phone = ?
  `;
  let values = [name, gender, phone];

  // Only update profile_photo if a new file was uploaded
  if (newPhotoPath) {
    sql += ", profile_photo = ?";
    values.push(newPhotoPath);
  }

  sql += " WHERE id = ?";
  values.push(userId); 

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error("❌ Error updating profile:", err);
      return res.status(500).json({ message: "Error updating profile data" });
    }
    
    // Fetch and return the updated profile for immediate client refresh
    db.query(
      "SELECT id, name, email, gender, phone, profile_photo FROM users WHERE id = ?",
      [userId],
      (err2, results) => {
          if (err2 || results.length === 0) {
            return res.status(500).json({ message: "Profile updated, but failed to fetch latest data" });
          }

          const updatedUser = results[0];
          // Set full URL for profile photo
          if (updatedUser.profile_photo) {
              const photoPath = updatedUser.profile_photo.startsWith("/") 
                  ? updatedUser.profile_photo 
                  : `/uploads/${updatedUser.profile_photo.replace('/uploads/', '')}`;
              updatedUser.profile_photo = `http://localhost:5050${photoPath}`;
          } else {
              updatedUser.profile_photo = "http://localhost:5050/uploads/default.png";
          }
          
          res.json({ 
              message: "Profile updated successfully!",
              user: updatedUser
          });
      }
    );
  });
});


// ============================
// ✅ Start Server
// ============================
const PORT = process.env.PORT || 5050;
const HOST = "0.0.0.0";

app.listen(PORT, HOST, () => {
  console.log(`🚀 Server running on http://${HOST}:${PORT}`);
});