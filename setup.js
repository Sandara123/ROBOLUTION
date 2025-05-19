const fs = require('fs');
const path = require('path');

// Define all required directories
const directories = [
    path.join(__dirname, 'public'),
    path.join(__dirname, 'public', 'uploads'),
    path.join(__dirname, 'public', 'uploads', 'temp'),
    path.join(__dirname, 'public', 'images')
];

// Create directories if they don't exist
directories.forEach(dir => {
    if (!fs.existsSync(dir)) {
        console.log(`Creating directory: ${dir}`);
        fs.mkdirSync(dir, { recursive: true });
    } else {
        console.log(`Directory already exists: ${dir}`);
    }
});

console.log('Setup complete!'); 