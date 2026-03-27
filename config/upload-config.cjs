/**
 * UPLOAD CONFIG – Multer configuration (consolidate file upload logic)
 */

const multer = require("multer");
const path = require("path");
const fs = require("fs");

// Ensure upload directories exist
const ensureUploadDirs = () => {
  ["uploads", "uploads/resumes", "uploads/photos"].forEach((dir) => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  });
};

// Multer storage config
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(
      null,
      file.fieldname === "resume" ? "uploads/resumes" : "uploads/photos"
    );
  },
  filename: (req, file, cb) => {
    const cleanName = path.basename(file.originalname).replace(/\s/g, "-");
    cb(null, Date.now() + "-" + cleanName);
  },
});

// File upload filter
const fileFilter = (req, file, cb) => {
  if (file.fieldname === "photo") {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Only image files are allowed for photo"));
  } else if (file.fieldname === "resume") {
    if (file.mimetype === "application/pdf") cb(null, true);
    else cb(new Error("Only PDF files are allowed for resume"));
  } else cb(null, true);
};

// Create upload middleware
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter,
});

// Convert file to data URL
const fileToDataUrl = (filePath, mimeType = "image/jpeg") => {
  const absPath = path.isAbsolute(filePath)
    ? filePath
    : path.join(__dirname, "..", filePath);
  const bytes = fs.readFileSync(absPath);
  return `data:${mimeType};base64,${bytes.toString("base64")}`;
};

module.exports = {
  ensureUploadDirs,
  upload,
  fileToDataUrl,
};
