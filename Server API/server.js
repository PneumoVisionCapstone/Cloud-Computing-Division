const express = require("express");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const FormData = require("form-data");
const { Storage } = require("@google-cloud/storage");
const stream = require("stream");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());
app.use(bodyParser.text());
app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // Middleware untuk file statis

const db = mysql.createConnection({
  host: "34.101.242.156",
  user: "root",
  password: "X^Q+GN%n@C=c%3}c",
  database: "UserAccount",
});

const storage = new Storage({
  keyFilename: "key/cloudkey.json", // Ganti dengan lokasi file JSON kredensial Anda
  projectId: "useful-airlock-425215-n6", // Ganti dengan ID proyek Google Cloud Anda
});

const bucket = storage.bucket("mycapstone-user-profile-picture"); // Ganti dengan nama bucket Anda
const multerStorage = multer.memoryStorage();
const jwtSecret = "2lmBFtAY0HybUp1L74qGTerX1YgIgNHn";
const PORT = process.env.PORT || 8080;

const upload = multer({
  storage: multerStorage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5 MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Not an image file!"), false);
    }
  },
});

app.get("/", (req, res) => {
  res.send("Welcome to the API!");
});

const generateToken = (userId) => {
  return jwt.sign({ id: userId }, jwtSecret, { expiresIn: "24h" });
};

// Middleware to authenticate and verify token
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res
      .status(403)
      .json({ error: "A token is required for authentication" });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;

    // Check if the token is blacklisted
    db.query(
      "SELECT token FROM blacklist WHERE token = ?",
      [token],
      (err, results) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        if (results.length > 0) {
          return res.status(401).json({ error: "Token is blacklisted" });
        }

        next();
      }
    );
  } catch (err) {
    return res.status(401).json({ error: "Invalid Token" });
  }
};

// Endpoint for registration
app.post("/register", upload.single("profile_picture"), async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const emailCheckSql = "SELECT email FROM users WHERE email = ?";
    db.query(emailCheckSql, [email], async (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (results.length > 0) {
        return res.status(409).json({ error: "Email already in use" });
      }

      let profilePictureUrl = null;
      if (req.file) {
        const blob = bucket.file(`${Date.now()}-${req.file.originalname}`);
        const blobStream = blob.createWriteStream({
          resumable: false,
          metadata: {
            contentType: req.file.mimetype,
          },
        });

        const bufferStream = new stream.PassThrough();
        bufferStream.end(req.file.buffer);
        bufferStream.pipe(blobStream);

        await new Promise((resolve, reject) => {
          blobStream.on("finish", resolve);
          blobStream.on("error", reject);
        });

        profilePictureUrl = `https://storage.googleapis.com/${bucket.name}/${blob.name}`;
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const insertSql =
        "INSERT INTO users (name, email, password, profile_picture) VALUES (?, ?, ?, ?)";
      db.query(
        insertSql,
        [name, email, hashedPassword, profilePictureUrl],
        (err, results) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          res.status(201).json({ message: "User registered" });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint for login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (results.length === 0) {
        return res.status(401).json({ error: "User not found" });
      }

      const user = results[0];
      if (await bcrypt.compare(password, user.password)) {
        const token = generateToken(user.id); // Generate token
        res.status(200).json({ message: "Login successful", token });
      } else {
        res.status(401).json({ error: "Invalid password" });
      }
    }
  );
});

// Endpoint for retrieving registered users
app.get("/users", authenticateToken, (req, res) => {
  db.query("SELECT name, email, profile_picture FROM users", (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json(results);
  });
});

//Endpoint for LogOut
app.post("/logout", authenticateToken, (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  db.query(
    "INSERT INTO blacklist (token) VALUES (?)",
    [token],
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.status(200).json({ message: "Logout successful" });
    }
  );
});

//Endpoint for profile
app.get("/profile", authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query(
    "SELECT name, email, profile_picture FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const user = results[0];
      res.status(200).json(user);
    }
  );
});

// Endpoint for updating user profile
app.put(
  "/profile",
  authenticateToken,
  upload.single("profile_picture"),
  async (req, res) => {
    const userId = req.user.id;
    const { name } = req.body;

    let profilePictureUrl = null;
    if (req.file) {
      try {
        profilePictureUrl = await uploadImageToStorage(req.file); // Mengunggah gambar baru ke Google Cloud
      } catch (error) {
        return res.status(500).json({ error: error.message });
      }
    }

    let updateSql = "UPDATE users SET ";
    const updateFields = [];
    const updateValues = [];

    if (name) {
      updateFields.push("name = ?");
      updateValues.push(name);
    }

    if (profilePictureUrl) {
      updateFields.push("profile_picture = ?");
      updateValues.push(profilePictureUrl);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: "No fields to update" });
    }

    updateSql += updateFields.join(", ") + " WHERE id = ?";
    updateValues.push(userId);

    try {
      await db.promise().query(updateSql, updateValues);
      res.status(200).json({ message: "Profile updated successfully" });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }
);

async function uploadImageToStorage(file) {
  const blob = bucket.file(`${Date.now()}-${file.originalname}`);
  const blobStream = blob.createWriteStream({
    resumable: false,
    metadata: {
      contentType: file.mimetype,
    },
  });

  const bufferStream = new stream.PassThrough();
  bufferStream.end(file.buffer);
  return new Promise((resolve, reject) => {
    bufferStream
      .pipe(blobStream)
      .on("finish", () => {
        resolve(`https://storage.googleapis.com/${bucket.name}/${blob.name}`);
      })
      .on("error", reject);
  });
}

/*async function deleteImageFromStorage(url) {
  if (!url) return; // Jika tidak ada URL, tidak ada yang perlu dihapus

  try {
    const fileName = url.split("/").pop(); // Ekstrak nama file dari URL
    const file = bucket.file(fileName);
    await file.delete(); // Menghapus file dari bucket
    console.log(`Successfully deleted ${fileName}`);
  } catch (error) {
    console.error(`Failed to delete old profile picture: ${error.message}`);
    throw new Error(`Failed to delete old profile picture: ${error.message}`);
  }
}*/

// Endpoint untuk menerima data pengguna dan mengirimkan foto ke API kedua
app.post(
  "/predict",
  authenticateToken,
  upload.single("photo"),
  async (req, res) => {
    const { name, gender, age } = req.body;
    const photo = req.file;
    const userId = req.user.id; // Mendapatkan user ID dari token

    if (!name || !gender || !age || !photo) {
      return res.status(400).json({ error: "All fields are required" });
    }

    let photoUrl = null;
    try {
      photoUrl = await uploadPredictionImageToStorage(photo); // Menggunakan fungsi baru untuk upload
    } catch (error) {
      return res
        .status(500)
        .json({ error: "Failed to upload image: " + error.message });
    }

    try {
      // Kirim foto ke API kedua
      const formData = new FormData();
      if (photo.buffer) {
        formData.append("file", photo.buffer, photo.originalname); // Menggunakan buffer langsung
      }

      const response = await axios.post(
        "https://predict-5cveqbjt2a-et.a.run.app/predict",
        formData,
        {
          headers: formData.getHeaders(),
        }
      );

      // Tunggu respons dari API kedua dan kembalikan ke client
      const probabilities = response.data.probabilities;
      let message = "Pasien sehat";
      if (probabilities >= 0.5) {
        message = "Berkemungkinan terkena pneumonia";
      }

      // Simpan hasil prediksi ke database
      const insertSql =
        "INSERT INTO predictions (user_id, name, gender, age, photo, probabilities, message) VALUES (?, ?, ?, ?, ?, ?, ?)";
      db.query(
        insertSql,
        [
          userId,
          name,
          gender,
          age,
          photoUrl,
          JSON.stringify(probabilities),
          message,
        ],
        (err, results) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          res.status(200).json({ message, probabilities });
        }
      );
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

//function for store predicition image to cloud storage
const predictionBucket = storage.bucket("mycapstone-prediction-picture"); // Tentukan nama bucket untuk prediksi
async function uploadPredictionImageToStorage(file) {
  const blob = predictionBucket.file(`${Date.now()}-${file.originalname}`);
  const blobStream = blob.createWriteStream({
    resumable: false,
    metadata: {
      contentType: file.mimetype,
    },
  });

  const bufferStream = new stream.PassThrough();
  bufferStream.end(file.buffer);
  return new Promise((resolve, reject) => {
    bufferStream
      .pipe(blobStream)
      .on("finish", () => {
        resolve(
          `https://storage.googleapis.com/${predictionBucket.name}/${blob.name}`
        );
      })
      .on("error", reject);
  });
}

// Endpoint untuk mendapatkan riwayat prediksi pengguna
app.get("/predictions", authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query(
    "SELECT id, name, gender, age, photo, probabilities, message, created_at FROM predictions WHERE user_id = ? ORDER BY created_at DESC",
    [userId],
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.status(200).json(results);
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
