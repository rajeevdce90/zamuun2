const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { PythonShell } = require('python-shell');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configure multer for file upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        const allowedExtensions = ['.csv', '.json'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedExtensions.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Only CSV and JSON files are allowed'));
        }
    },
    limits: {
        fileSize: 16 * 1024 * 1024 // 16MB max file size
    }
});

// Serve static files from the templates directory
app.use(express.static('templates'));

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'index.html'));
});

app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const filePath = req.file.path;
    
    // Configure Python Shell options
    const options = {
        mode: 'json',
        pythonPath: 'python',
        pythonOptions: ['-u'], // unbuffered output
        scriptPath: __dirname,
        args: [filePath]
    };

    // Run the Python analysis script
    PythonShell.run('analyze_logs.py', options)
        .then(results => {
            // Clean up the uploaded file
            fs.unlinkSync(filePath);
            
            // Send the analysis results
            res.json(results[0]);
        })
        .catch(err => {
            // Clean up the uploaded file in case of error
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
            console.error('Error:', err);
            res.status(500).json({ error: 'Error analyzing log file' });
        });
});

// Error handling middleware
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File size too large. Maximum size is 16MB.' });
        }
        return res.status(400).json({ error: err.message });
    }
    
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
}); 