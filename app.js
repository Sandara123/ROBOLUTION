// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const app = express();
const port = process.env.SERVER_PORT || process.env.PORT || 3000;
const mongoose = require('mongoose');
const moment = require('moment'); // Added moment
const Post = require('./models/Post');
const multer = require('multer');  // To handle file uploads
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Category = require('./models/Category');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const Registration = require('./models/Registration');
const User = require('./models/User');
const fetch = require('node-fetch'); // For fetching files from Cloudinary
const qrcode = require('qrcode');
const { exec } = require('child_process'); // For executing system commands
const { ObjectId } = require('mongodb'); // Added for ObjectId usage
const axios = require('axios');

// Try to load connect-flash if available, but don't fail if it's not
let flash;
try {
  flash = require('connect-flash');
} catch (err) {
  console.log('connect-flash not available, will use simple flash messages');
  flash = null;
}

// Define Admin model placeholder
// Note: The actual Admin model is defined after database connection setup
const cloudinary = require('cloudinary').v2; // Add Cloudinary
const MongoStore = require('connect-mongo');
const speakeasy = require('speakeasy');

// Trust proxy - required for secure cookies in production
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

// Create necessary directories
const requiredDirs = [
  path.join(__dirname, 'public'),
  path.join(__dirname, 'public/uploads'),
  path.join(__dirname, 'public/uploads/temp'),
  path.join(__dirname, 'public/images'),
  path.join(__dirname, 'public/css'),
  path.join(__dirname, 'public/js')
];

requiredDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`Created directory: ${dir}`);
  }
});

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Add debug logging
console.log('Cloudinary Configuration:', {
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  hasSecret: !!process.env.CLOUDINARY_API_SECRET
});

// MongoDB connection string - using environment variables
const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error("ERROR: MONGODB_URI environment variable is not set in .env file");
  process.exit(1); // Exit the application if the connection string is not available
}

// Define variables for database access
let db; // For adminDB access
let robolutionDb; // For direct robolution database access

// Set up session middleware before routes
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secure-admin-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        dbName: 'robolution',
        collectionName: 'sessions',
        ttl: 24 * 60 * 60, // Session TTL in seconds (1 day)
        autoRemove: 'native', // Enable automatic removal of expired sessions
        crypto: {
            secret: process.env.SESSION_SECRET || 'your-secure-admin-key'
        }
    }),
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Only use secure cookies in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Required for cross-site cookies in production
        path: '/' // Ensure cookie is available for all routes
    },
    name: 'robolution_session',
    proxy: true // Trust the reverse proxy
}));

// Set up flash middleware after session if available
if (flash) {
  app.use(flash());
}

// Add better session debugging
app.use((req, res, next) => {
    console.log('Session Debug:', {
        url: req.url,
        method: req.method,
        sessionID: req.sessionID,
        session: {
            hasSession: !!req.session,
            isAuthenticated: !!req.session?.user,
            isAdmin: req.session?.user?.isAdmin,
            username: req.session?.user?.username
        },
        store: {
            type: 'MongoStore',
            connected: !!req.session?.store
        }
    });
    next();
});

// Add middleware to make user and flash messages available to all views
app.use((req, res, next) => {
    res.locals.user = req.session?.user || null;
    
    // Create a simple flash implementation if connect-flash isn't available
    if (!req.flash) {
        // Store flash messages in session
        if (!req.session.flashMessages) {
            req.session.flashMessages = { success: [], error: [] };
        }
        
        // Define flash function
        req.flash = function(type, message) {
            console.log(`Flash message: ${type} - ${message}`);
            if (!req.session.flashMessages[type]) {
                req.session.flashMessages[type] = [];
            }
            req.session.flashMessages[type].push(message);
            return req.session.flashMessages[type];
        };
        
        // Expose flash messages to templates
        res.locals.flashMessages = {
            success: req.session.flashMessages.success || [],
            error: req.session.flashMessages.error || []
        };
        
        // Clear flash messages after they're consumed
        req.session.flashMessages = { success: [], error: [] };
    } else {
        // Use connect-flash as normal
        res.locals.flashMessages = {
            success: req.flash('success') || [],
            error: req.flash('error') || []
        };
    }
    
    next();
});

// Add cache control middleware for authenticated routes
app.use((req, res, next) => {
  // If user is logged in, set no-cache headers to prevent browser caching
  if (req.session && req.session.user) {
    res.set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Surrogate-Control': 'no-store'
    });
  }
  next();
});

// MongoDB Backup Functionality
const setupDatabaseBackups = () => {
  const backupsDir = path.join(__dirname, 'database_backups');
  
  // Create backups directory if it doesn't exist - we'll still use this for temporary storage
  if (!fs.existsSync(backupsDir)) {
    fs.mkdirSync(backupsDir, { recursive: true });
    console.log(`Created database backups directory: ${backupsDir}`);
  }
  
  // Function to perform database backup using MongoDB driver directly and upload to Cloudinary
  const backupDatabase = async () => {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupId = `backup-${timestamp}`;
      const backupPath = path.join(__dirname, 'database_backups', backupId);
      
      // Create timestamp directory for temporary storage
      if (!fs.existsSync(backupPath)) {
        fs.mkdirSync(backupPath, { recursive: true });
      }
      
      console.log(`Starting MongoDB backup to: ${backupPath}`);
      
      // Get a client to the MongoDB database
      const client = await MongoClient.connect(process.env.MONGODB_URI);
      const dbName = 'robolution'; // Your database name
      const db = client.db(dbName);
      
      // Get all collections in the database
      const collections = await db.listCollections().toArray();
      
      // Store information about all files uploaded
      const uploadedFiles = [];
      
      // For each collection, export all documents to a JSON file and upload to Cloudinary
      for (const collection of collections) {
        const collectionName = collection.name;
        const documents = await db.collection(collectionName).find({}).toArray();
        
        // Convert MongoDB objects to JSON-compatible format
        // This is important for handling ObjectIDs and other special MongoDB types correctly
        const jsonReadyDocuments = documents.map(doc => {
          const processedDoc = {};
          
          // Process each field in the document
          Object.keys(doc).forEach(key => {
            const value = doc[key];
            
            // Handle ObjectID specifically - preserve as string but with type information
            if (value && value.constructor && (value.constructor.name === 'ObjectID' || value.constructor.name === 'ObjectId')) {
              processedDoc[key] = value.toString();
            } 
            // Handle Date objects
            else if (value instanceof Date) {
              processedDoc[key] = { 
                $date: value.toISOString() 
              };
            }
            // Handle nested objects (could contain ObjectIDs)
            else if (value && typeof value === 'object' && !Array.isArray(value)) {
              const nestedObj = {};
              Object.keys(value).forEach(nestedKey => {
                const nestedValue = value[nestedKey];
                if (nestedValue && nestedValue.constructor && 
                    (nestedValue.constructor.name === 'ObjectID' || nestedValue.constructor.name === 'ObjectId')) {
                  nestedObj[nestedKey] = nestedValue.toString();
                } else {
                  nestedObj[nestedKey] = nestedValue;
                }
              });
              processedDoc[key] = nestedObj;
            } 
            // Handle arrays (could contain ObjectIDs or other special types)
            else if (Array.isArray(value)) {
              processedDoc[key] = value.map(item => {
                if (item && item.constructor && (item.constructor.name === 'ObjectID' || item.constructor.name === 'ObjectId')) {
                  return item.toString();
                }
                return item;
              });
            } 
            // Default case: use the value as is
            else {
              processedDoc[key] = value;
            }
          });
          
          return processedDoc;
        });
        
        // Save documents to a JSON file temporarily
        const collectionFile = path.join(backupPath, `${collectionName}.json`);
        fs.writeFileSync(collectionFile, JSON.stringify(jsonReadyDocuments, null, 2));
        console.log(`Created temporary backup file for collection: ${collectionName} with ${documents.length} documents`);
        
        // Upload the JSON file to Cloudinary
        const cloudinaryResult = await uploadToCloudinary(collectionFile, `robolution/backups/${backupId}`);
        uploadedFiles.push({
          collection: collectionName,
          url: cloudinaryResult,
          documentCount: documents.length
        });
        console.log(`Uploaded backup for collection ${collectionName} to Cloudinary`);
      }
      
      // Write metadata about the backup
      const metadata = {
        timestamp: timestamp,
        date: new Date().toString(),
        databaseName: dbName,
        collections: collections.map(c => c.name),
        backupType: 'cloudinary_export',
        files: uploadedFiles,
        format: 'json_with_objectid_strings' // Add format information to help with restore
      };
      
      // Save metadata file
      const metadataFile = path.join(backupPath, 'backup-metadata.json');
      fs.writeFileSync(metadataFile, JSON.stringify(metadata, null, 2));
      
      // Upload metadata file to Cloudinary
      const metadataUrl = await uploadToCloudinary(metadataFile, `robolution/backups/${backupId}`);
      
      // Save backup record to the database so we can list backups later
      await db.collection('database_backups').insertOne({
        backupId,
        timestamp: new Date(),
        metadataUrl,
        files: uploadedFiles,
        format: 'json_with_objectid_strings', // Store format information
        size: uploadedFiles.reduce((acc, file) => acc + (file.size || 0), 0)
      });
      
      console.log(`MongoDB backup successful. Metadata stored at: ${metadataUrl}`);
      
      // Clean up temporary files
      try {
        fs.rm(backupPath, { recursive: true, force: true }, (err) => {
          if (err) {
            console.error(`Error cleaning up temporary backup files: ${err.message}`);
          } else {
            console.log(`Cleaned up temporary backup directory: ${backupPath}`);
          }
        });
      } catch (cleanupError) {
        console.error(`Error during backup cleanup: ${cleanupError.message}`);
      }
      
      // Close the client
      await client.close();
      
      // Rotate backups - keep only the last 48 backups
      rotateCloudinaryBackups(48);
    } catch (error) {
      console.error(`Database backup error:`, error);
    }
  };
  
  // Function to rotate backups (delete oldest backups keeping only the latest n)
  const rotateCloudinaryBackups = async (keepCount) => {
    try {
      // Connect to the database
      const client = await MongoClient.connect(process.env.MONGODB_URI);
      const db = client.db('robolution');
      
      // Get all backups sorted by date (oldest first)
      const backups = await db.collection('database_backups')
        .find({})
        .sort({ timestamp: 1 })
        .toArray();
      
      // If we have more backups than keepCount, delete the oldest ones
      if (backups.length > keepCount) {
        const toDelete = backups.slice(0, backups.length - keepCount);
        
        for (const backup of toDelete) {
          console.log(`Deleting old backup: ${backup.backupId}`);
          
          // Delete each file from Cloudinary
          for (const file of backup.files) {
            if (file.url) {
              try {
                // Extract public_id from Cloudinary URL
                const urlParts = file.url.split('/');
                const publicId = `robolution/backups/${backup.backupId}/${urlParts[urlParts.length - 1].split('.')[0]}`;
                
                // Delete from Cloudinary
                await cloudinary.uploader.destroy(publicId);
                console.log(`Deleted Cloudinary file: ${publicId}`);
              } catch (err) {
                console.error(`Error deleting Cloudinary file: ${err.message}`);
              }
            }
          }
          
          // Delete metadata from Cloudinary if it exists
          if (backup.metadataUrl) {
            try {
              const urlParts = backup.metadataUrl.split('/');
              const publicId = `robolution/backups/${backup.backupId}/${urlParts[urlParts.length - 1].split('.')[0]}`;
              
              await cloudinary.uploader.destroy(publicId);
              console.log(`Deleted Cloudinary metadata file: ${publicId}`);
            } catch (err) {
              console.error(`Error deleting Cloudinary metadata file: ${err.message}`);
            }
          }
          
          // Delete the backup record from the database
          await db.collection('database_backups').deleteOne({ _id: backup._id });
          console.log(`Deleted backup record from database: ${backup.backupId}`);
        }
      }
      
      // Close the client
      await client.close();
    } catch (error) {
      console.error('Error rotating backups:', error);
    }
  };

  // Schedule hourly backups
  console.log('Setting up scheduled database backups (hourly)');
  setInterval(() => {
    backupDatabase().catch(err => {
      console.error('Scheduled backup error:', err);
    });
  }, 60 * 60 * 1000); // Every hour
  
  // Run a backup immediately on startup
  console.log('Running initial database backup on startup');
  backupDatabase().catch(err => {
    console.error('Initial backup error:', err);
  });
};

// Connect MongoDB for both Mongoose and MongoClient
mongoose.connect(uri, { dbName: 'robolution' })
  .then(() => {
    console.log("Connected to MongoDB Atlas with Mongoose using robolution database");
    return MongoClient.connect(uri);
  })
  .then(client => {
    // Set the db variable to access the adminDB for admin operations
    db = client.db('adminDB');
    console.log('MongoDB client connected to adminDB for admin operations');
    
    // Also access the robolution database for direct operations if needed
    robolutionDb = client.db('robolution');
    console.log('MongoDB client can also access robolution database');
    
    // Ensure database_backups collection exists
    robolutionDb.listCollections({ name: 'database_backups' })
      .toArray()
      .then(collections => {
        if (collections.length === 0) {
          console.log('Creating database_backups collection for backup management');
          robolutionDb.createCollection('database_backups');
        }
      })
      .catch(err => console.error('Error checking for database_backups collection:', err));
    
    // Check admins collection exists in robolution database as well
    robolutionDb.listCollections({ name: 'admins' })
      .toArray()
      .then(collections => {
        if (collections.length === 0) {
          console.log('Warning: no admins collection in robolution database');
          // Check if we have admins in adminDB and sync them
          db.collection('admins').find({}).toArray()
            .then(admins => {
              if (admins && admins.length > 0) {
                console.log('Found admins in adminDB, copying to robolution database for redundancy');
                robolutionDb.createCollection('admins')
                  .then(() => robolutionDb.collection('admins').insertMany(admins))
                  .then(() => console.log('Admin accounts synced to robolution database'))
                  .catch(err => console.error('Error syncing admin accounts:', err));
              }
            })
            .catch(err => console.error('Error checking adminDB collection:', err));
        }
      })
      .catch(err => console.error('Error checking for admins collection:', err));
    
    // Start the database backup system
    setupDatabaseBackups();
    
    console.log('==> Your service is live 🎉');
  })
  .catch(err => console.error('MongoDB connection error:', err));

// Function to calculate file hash
function calculateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('md5');
    const stream = fs.createReadStream(filePath);
    
    stream.on('error', err => reject(err));
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

// Function to find duplicate image
async function findDuplicateImage(filePath) {
  const uploadsDir = path.join(__dirname, 'public', 'uploads');
  const newFileHash = await calculateFileHash(filePath);
  
  const files = fs.readdirSync(uploadsDir);
  for (const file of files) {
    const existingFilePath = path.join(uploadsDir, file);
    if (existingFilePath !== filePath) { // Don't compare with self
      try {
        const existingHash = await calculateFileHash(existingFilePath);
        if (existingHash === newFileHash) {
          return '/uploads/' + file; // Return the path of duplicate file
        }
      } catch (err) {
        console.error('Error checking file:', file, err);
      }
    }
  }
  return null;
}

// Set up multer storage configuration for temporary file storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'public', 'uploads', 'temp');
        // Ensure directory exists
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        // Add file type validation
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Not an image! Please upload an image file.'), false);
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Helper function to upload file to Cloudinary
async function uploadToCloudinary(filePath, folder = 'robolution') {
  try {
    const result = await cloudinary.uploader.upload(filePath, {
      folder: folder,
      resource_type: 'auto' // Auto-detect resource type (image/video)
    });
    // Delete the temporary file after successful upload
    fs.unlinkSync(filePath);
    return result.secure_url;
  } catch (error) {
    console.error('Error uploading to Cloudinary:', error);
    throw error;
  }
}

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));  // To serve static files
app.use(express.json());

// Protected route middleware
const requireAdmin = (req, res, next) => {
    console.log('Checking admin access:', {
        hasSession: !!req.session,
        user: req.session?.user
    });
    
    if (!req.session || !req.session.user || !req.session.user.isAdmin) {
        console.log('Unauthorized access attempt');
        return res.redirect('/login');
    }
    
    // Validate admin exists in database before proceeding
    const validateAdminUser = async () => {
        try {
            // Check admin database directly using the native MongoDB driver
            console.log('Validating admin access for:', req.session.user.username);
            
            const ObjectId = require('mongodb').ObjectId;
            let adminId;
            
            try {
                // Try converting to ObjectId if possible
                if (req.session.user.id && req.session.user.id.length === 24) {
                    adminId = new ObjectId(req.session.user.id);
                }
            } catch (err) {
                console.log('Error converting admin ID to ObjectId:', err.message);
            }
            
            // Check for admin by ID or username
            const adminQuery = { $or: [] };
            
            // Add ID queries for both string and ObjectId formats
            if (adminId) {
                adminQuery.$or.push({ _id: adminId });
            }
            if (req.session.user.id) {
                adminQuery.$or.push({ _id: req.session.user.id });
            }
            
            // Add username query
            if (req.session.user.username) {
                adminQuery.$or.push({ username: req.session.user.username });
            }
            
            // Check if we have any valid query conditions
            if (adminQuery.$or.length === 0) {
                console.log('No valid admin identification found in session');
                req.session.destroy();
                return res.redirect('/login');
            }
            
            // Try to find admin using MongoDB client
            let adminFound = false;
            
            // First check in adminDB, which is the native MongoDB connection
            if (db) {
                console.log('Checking admin in adminDB:', JSON.stringify(adminQuery));
                const adminUser = await db.collection('admins').findOne(adminQuery);
                if (adminUser) {
                    console.log('Admin validated in adminDB collection');
                    adminFound = true;
                }
            }
            
            // Also check robolution database as a fallback
            if (!adminFound && robolutionDb) {
                console.log('Checking admin in robolution database');
                const adminUser = await robolutionDb.collection('admins').findOne(adminQuery);
                
                if (adminUser) {
                    console.log('Admin validated in robolution admins collection');
                    adminFound = true;
                }
            }
            
            if (!adminFound) {
                console.log('Admin not found in any database:', req.session.user.username || req.session.user.id);
                req.session.destroy();
                return res.redirect('/login?message=session_invalid');
            }
            
            // Admin exists, proceed to the next middleware
            next();
        } catch (error) {
            console.error('Error validating admin:', error);
            // Instead of just next(), handle the error more strictly:
            req.session.destroy(err => {
                if (err) {
                    console.error('Error destroying session during admin validation failure:', err);
                }
                return res.redirect('/login?message=admin_validation_error');
            });
        }
    };
    
    // Run validation
    validateAdminUser();
};

app.use('/images', express.static('public/images', {
  setHeaders: (res, path) => {
    if (path.endsWith('.webm')) {
      res.setHeader('Content-Type', 'video/webm');
    }
  }
}));

// Configure view engine
app.set('view engine', 'ejs');
// Set up multiple view paths - add userViews folder
app.set('views', [
  path.join(__dirname, 'views'),
  path.join(__dirname, 'views/UserViews')
]);

// Middleware to make unique regions available to all templates
app.use(async (req, res, next) => {
  try {
    // Only fetch unique regions once every few minutes to avoid excessive DB queries
    const currentTime = Date.now();
    if (!app.locals.uniqueRegionsLastFetched || currentTime - app.locals.uniqueRegionsLastFetched > 5 * 60 * 1000) {
      const allPosts = await Post.find();
      app.locals.uniqueRegions = [...new Set(allPosts.map(post => post.region).filter(region => region && region !== 'All'))].sort();
      app.locals.uniqueRegionsLastFetched = currentTime;
    }
    
    // Make uniqueRegions available to all templates
    res.locals.uniqueRegions = app.locals.uniqueRegions || [];
    next();
  } catch (error) {
    console.error('Error fetching unique regions:', error);
    res.locals.uniqueRegions = [];
    next();
  }
});

// Update create post route with middleware
app.get('/create-post', requireAdmin, async (req, res) => {
    try {
        const isDashboard = req.query.dashboard === 'true';
        // Get unique regions for the dropdown
        const allPosts = await Post.find();
        const uniqueRegions = [...new Set(allPosts.map(post => post.region).filter(region => region && region !== 'All'))].sort();
        
        console.log("Create Post Route Hit - User:", req.session.user);
        res.render('create-post', { 
            uniqueRegions,
            user: req.session.user,
            dashboard: isDashboard // Pass dashboard status
        });
    } catch (error) {
        console.error('Error loading create post page:', error);
        res.status(500).send('Error loading create post page');
    }
});

app.get('/login', (req, res) => {
  console.log("login Route Hit");  // Check if route is being hit
  res.render('UserViews/login');
});

app.get('/user-landing', async (req, res) => {
  try {
    console.log('Accessing user landing page');
    
    const sortDirection = req.query.sort === 'asc' ? 1 : -1;
    
    // DIRECT COLLECTION ACCESS
    const postsCollection = robolutionDb.collection('posts');
    
    // Fetch all posts using native MongoDB
    let posts = await postsCollection.find().sort({ createdAt: sortDirection }).toArray();
    console.log(`Found ${posts.length} posts for user landing`);
    
    // Convert MongoDB documents to JavaScript objects
    posts = JSON.parse(JSON.stringify(posts));
    
    res.render('UserViews/user-landing', { 
      posts, 
      sort: req.query.sort || 'desc'
    });
  } catch (error) {
    console.error('Error in user-landing route:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Route to show all posts - changed to redirect to user landing
app.get('/', async (req, res) => {
  res.redirect('/user-landing');
});

// Admin index page with direct MongoDB access
app.get('/index', requireAdmin, async (req, res) => { // Added requireAdmin here
  try {
    const isDashboard = req.query.dashboard === 'true';
    console.log('Accessing admin index page');
    
    const sortDirection = req.query.sort === 'asc' ? 1 : -1;
    
    // DIRECT COLLECTION ACCESS
    const postsCollection = robolutionDb.collection('posts');
    
    // Fetch all posts using native MongoDB
    let posts = await postsCollection.find().sort({ createdAt: sortDirection }).toArray();
    console.log(`Found ${posts.length} posts for admin index`);
    
    // Convert MongoDB documents to JavaScript objects
    posts = JSON.parse(JSON.stringify(posts));
    
    res.render('index', { 
        posts, 
        sort: req.query.sort || 'desc',
        user: req.session.user, // Pass user session
        uniqueRegions: res.locals.uniqueRegions, // Pass uniqueRegions
        dashboard: isDashboard // Pass dashboard status
    });
  } catch (error) {
    console.error('Error fetching posts for admin index:', error);
    res.status(500).send('An error occurred while fetching posts');
  }
});

// Update post creation route with middleware
app.post('/posts', requireAdmin, upload.single('image'), async (req, res) => {
    try {
        const { title, content, author, date, useCurrentDate, region } = req.body;
        let imageUrl = '';

        if (req.file) {
            try {
                const filePath = req.file.path;
                console.log('Uploading file:', filePath);
                imageUrl = await uploadToCloudinary(filePath, 'robolution/posts');
                console.log('Cloudinary upload successful:', imageUrl);
            } catch (uploadError) {
                console.error('Error uploading to Cloudinary:', uploadError);
                return res.status(500).json({ 
                    success: false, 
                    message: 'Error uploading image' 
                });
            }
        }

        let createdAt;
        if (useCurrentDate === "on" || !date) {
            createdAt = new Date();
        } else {
            createdAt = new Date(date);
        }

        const post = await Post.create({ 
            title, 
            content, 
            imageUrl, 
            author, 
            region: region || 'All',
            createdAt 
        });

        console.log('Post created successfully:', post);
        res.redirect('/index');
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).send('Error creating post: ' + error.message);
    }
});

// Route to show all categories with direct MongoDB access
app.get('/categories', async (req, res) => {
  try {
    console.log('Accessing categories page');
    
    // DIRECT COLLECTION ACCESS
    const categoriesCollection = robolutionDb.collection('categories');
    
    // Fetch all categories using native MongoDB
    let categories = await categoriesCollection.find().toArray();
    console.log(`Found ${categories.length} categories`);
    
    // Convert MongoDB documents to JavaScript objects
    categories = JSON.parse(JSON.stringify(categories));
    
    res.render('categories', { categories });
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).send('An error occurred while fetching categories');
  }
});

app.get('/user-categories', async (req, res) => {
  try {
    console.log('Accessing user categories page');
    
    // DIRECT COLLECTION ACCESS
    const categoriesCollection = robolutionDb.collection('categories');
    
    // Fetch all categories using native MongoDB
    let categories = await categoriesCollection.find().toArray();
    console.log(`Found ${categories.length} categories`);
    
    // Convert MongoDB documents to JavaScript objects
    categories = JSON.parse(JSON.stringify(categories));
    
    res.render('UserViews/user-categories', { categories });
  } catch (error) {
    console.error('Error fetching user categories:', error);
    res.status(500).send('An error occurred while fetching categories');
  }
});


// Route to show details for a specific category
app.get('/categories/:id', async (req, res) => {
  try {
    let category;
    
    try {
      // Try standard mongoose findById
      category = await Category.findById(req.params.id);
      
      // If not found and ID seems valid
      if (!category && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
        // Try with new ObjectId
        const ObjectId = mongoose.Types.ObjectId;
        const categoryId = new ObjectId(req.params.id);
        category = await Category.findOne({ _id: categoryId });
      }
      
      // Try as string ID if still not found
      if (!category) {
        category = await Category.findOne({ _id: req.params.id });
      }
    } catch (idError) {
      console.error('Error converting category ID:', idError);
      // Continue to check if category was found
    }
    
    if (category) {
      res.render('category-details', { event: category });
    } else {
      console.error('Event not found with ID:', req.params.id);
      res.status(404).send('Event not found');
    }
  } catch (error) {
    console.error('Error fetching category details:', error);
    res.status(500).send('An error occurred while fetching the category details');
  }
});

// Render manage categories page
app.get('/manage-categories', requireAdmin, async (req, res) => {
  try {
    const isDashboard = req.query.dashboard === 'true';
    const [categories, posts] = await Promise.all([
      Category.find(),
      Post.find()
    ]);

    // Get unique regions from posts
    const uniqueRegions = [...new Set(posts
      .map(post => post.region)
      .filter(region => region && region !== 'All')
    )].sort();

    res.render('manage-categories', { 
      categories,
      uniqueRegions
    });
  } catch (error) {
    console.error('Error loading manage categories:', error);
    res.status(500).send('Error loading manage categories');
  }
});

// Add new category with image upload
app.post('/manage-categories/add', upload.single('image'), async (req, res) => {
  try {
    const {
      title, description,
      mechanics, generalConduct, generalRules, participantsRequirement, teamRequirement,
      showMechanics, showGeneralConduct, showGeneralRules, showParticipantsRequirement, showTeamRequirement
    } = req.body;

    let imageUrl = '';
    
    if (req.file) {
      const filePath = path.join(__dirname, 'public', 'uploads', 'temp', req.file.filename);
      imageUrl = await uploadToCloudinary(filePath, 'robolution/categories');
    }

    await Category.create({
      title,
      description,
      imageUrl,
      mechanics: showMechanics ? (mechanics ? mechanics.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      generalConduct: showGeneralConduct ? (generalConduct ? generalConduct.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      generalRules: showGeneralRules ? (generalRules ? generalRules.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      participantsRequirement: showParticipantsRequirement ? (participantsRequirement ? participantsRequirement.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      teamRequirement: showTeamRequirement ? (teamRequirement ? teamRequirement.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      showMechanics: showMechanics === 'on',
      showGeneralConduct: showGeneralConduct === 'on',
      showGeneralRules: showGeneralRules === 'on',
      showParticipantsRequirement: showParticipantsRequirement === 'on',
      showTeamRequirement: showTeamRequirement === 'on'
    });
    res.redirect('/manage-categories');
  } catch (error) {
    console.error('Error adding category:', error);
    res.status(500).send('Error adding category');
  }
});

// Edit category with image upload
app.post('/manage-categories/edit/:id', upload.single('image'), async (req, res) => {
  try {
    const {
      title, description, currentImageUrl,
      mechanics, generalConduct, generalRules, participantsRequirement, teamRequirement,
      showMechanics, showGeneralConduct, showGeneralRules, showParticipantsRequirement, showTeamRequirement
    } = req.body;

    let imageUrl = currentImageUrl;

    if (req.file) {
      const filePath = path.join(__dirname, 'public', 'uploads', 'temp', req.file.filename);
      imageUrl = await uploadToCloudinary(filePath, 'robolution/categories');
    }

    const update = {
      title,
      description,
      imageUrl,
      mechanics: showMechanics ? (mechanics ? mechanics.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      generalConduct: showGeneralConduct ? (generalConduct ? generalConduct.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      generalRules: showGeneralRules ? (generalRules ? generalRules.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      participantsRequirement: showParticipantsRequirement ? (participantsRequirement ? participantsRequirement.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      teamRequirement: showTeamRequirement ? (teamRequirement ? teamRequirement.split('\n').map(m => m.trim()).filter(Boolean) : []) : [],
      showMechanics: showMechanics === 'on',
      showGeneralConduct: showGeneralConduct === 'on',
      showGeneralRules: showGeneralRules === 'on',
      showParticipantsRequirement: showParticipantsRequirement === 'on',
      showTeamRequirement: showTeamRequirement === 'on'
    };

    await Category.findByIdAndUpdate(req.params.id, update);
    res.redirect('/manage-categories');
  } catch (error) {
    console.error('Error updating category:', error);
    res.status(500).send('Error updating category');
  }
});

// Delete category and its image
app.post('/manage-categories/delete/:id', async (req, res) => {
  try {
    const category = await Category.findById(req.params.id);
    if (category && category.imageUrl) {
      const filePath = path.join(__dirname, 'public', category.imageUrl);
      // Check if any other category is using this image
      const otherCategories = await Category.find({
        _id: { $ne: req.params.id },
        imageUrl: category.imageUrl
      });
      
      if (otherCategories.length === 0 && fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
    await Category.findByIdAndDelete(req.params.id);
    res.redirect('/manage-categories');
  } catch (error) {
    console.error('Error deleting category:', error);
    res.status(500).send('Error deleting category');
  }
});

// Delete image from category
app.post('/manage-categories/:id/delete-image', async (req, res) => {
  try {
    const categoryId = req.params.id;
    const { imageUrl } = req.body;

    console.log('Attempting to delete image:', { categoryId, imageUrl });

    if (!categoryId || !imageUrl) {
      console.log('Missing required fields:', { categoryId, imageUrl });
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields' 
      });
    }

    // Find the category
    const category = await Category.findById(categoryId);
    if (!category) {
      console.log('Category not found:', categoryId);
      return res.status(404).json({ 
        success: false, 
        error: 'Category not found' 
      });
    }

    // Verify the image belongs to this category
    if (category.imageUrl !== imageUrl) {
      console.log('Image URL mismatch:', { 
        categoryImage: category.imageUrl, 
        requestedImage: imageUrl 
      });
      return res.status(400).json({ 
        success: false, 
        error: 'Image does not belong to this category' 
      });
    }

    // Check if other categories are using this image
    const otherCategories = await Category.find({
      _id: { $ne: categoryId },
      imageUrl: imageUrl
    });

    // If no other category is using this image, delete from Cloudinary
    if (otherCategories.length === 0) {
      try {
        // Extract public_id from Cloudinary URL
        const urlParts = imageUrl.split('/');
        const publicId = 'robolution/categories/' + urlParts[urlParts.length - 1].split('.')[0];
        
        console.log('Attempting to delete from Cloudinary with public_id:', publicId);
        const result = await cloudinary.uploader.destroy(publicId);
        console.log('Cloudinary deletion result:', result);
      } catch (cloudinaryError) {
        console.error('Error deleting from Cloudinary:', cloudinaryError);
        // Continue with category update even if Cloudinary deletion fails
      }
    } else {
      console.log('Image is used by other categories, keeping file');
    }

    // Update the category to remove the image reference
    await Category.findByIdAndUpdate(categoryId, { 
      $set: { imageUrl: '' } 
    });

    console.log('Category updated successfully');
    res.json({ success: true });
  } catch (error) {
    console.error('Error in delete-image route:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete image: ' + error.message 
    });
  }
});

// Route to show edit post page
app.get('/edit-post/:id', requireAdmin, async (req, res) => {
  // The following admin check is now handled by requireAdmin middleware and can be removed.
  // if (!req.session.user || !req.session.user.isAdmin) {
  //   return res.redirect('/login');
  // }

  try {
    // Get all posts for regions dropdown
    const posts = await Post.find();

    // Try to find the post by ID with proper ObjectID handling
    let post;
    
    try {
      // Try direct mongoose findById first
      post = await Post.findById(req.params.id);
      
      // If not found and ID seems to be a valid MongoDB ObjectId string
      if (!post && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
        // Create an ObjectId
        const ObjectId = mongoose.Types.ObjectId;
        const postId = new ObjectId(req.params.id);
        
        // Try alternative queries
        post = await Post.findOne({ _id: postId });
        
        if (!post) {
          post = await Post.findOne({ _id: req.params.id });
        }
      }
    } catch (idError) {
      console.error('Error looking up post:', idError);
      // Ignore error and try alternative lookup methods
    }

    if (!post) {
      console.error('Post not found with ID:', req.params.id);
      return res.status(404).send('Post not found');
    }

    // Get unique regions from posts
    const uniqueRegions = [...new Set(posts
      .map(post => post.region)
      .filter(region => region && region !== 'All')
    )].sort();

    res.render('edit-post', { 
      post,
      uniqueRegions
    });
  } catch (error) {
    console.error('Error finding post:', error);
    res.status(500).send('Server error');
  }
});

// Route to handle post update with direct MongoDB access
app.post('/edit-post/:id', requireAdmin, upload.single('image'), async (req, res) => {
  // Check if user is logged in and is an admin -- THIS CHECK WILL BE REMOVED
  // if (!req.session.user || !req.session.user.isAdmin) {
  //   return res.status(403).send('Unauthorized');
  // }
  
  try {
    console.log('Updating post with ID:', req.params.id);
    
    const { title, content, author, date, useCurrentDate, currentImageUrl, region } = req.body;
    
    let imageUrl = currentImageUrl;
    let createdAt;
    
    // Handle date
    if (useCurrentDate === "on" || !date) {
      createdAt = new Date();
    } else {
      createdAt = new Date(date);
    }
    
    // Handle image
    if (req.file) {
      const filePath = path.join(__dirname, 'public', 'uploads', 'temp', req.file.filename);
      imageUrl = await uploadToCloudinary(filePath, 'robolution/posts');
    }
    
    // Prepare the update data
    const updateData = { 
      title, 
      content, 
      author, 
      imageUrl,
      region: region || 'All',
      createdAt 
    };
    
    // DIRECT COLLECTION ACCESS
    const postsCollection = robolutionDb.collection('posts');
    
    // Find and update the post using multiple lookup approaches
    let updateResult = null;
    
    // 1. Try direct string ID update
    updateResult = await postsCollection.updateOne(
      { _id: req.params.id },
      { $set: updateData }
    );
    console.log('Direct string ID update result:', updateResult.matchedCount ? 'Found and updated' : 'Not found');
    
    // 2. Try ObjectID update if needed
    if (updateResult.matchedCount === 0 && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        updateResult = await postsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: updateData }
        );
        console.log('ObjectId update result:', updateResult.matchedCount ? 'Found and updated' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by title if still not found (as last resort)
    if (updateResult.matchedCount === 0) {
      updateResult = await postsCollection.updateOne(
        { title: title },
        { $set: updateData }
      );
      console.log('Title update result:', updateResult.matchedCount ? 'Found and updated' : 'Not found');
    }
    
    if (updateResult.matchedCount === 0) {
      console.error('Could not find post to update with ID:', req.params.id);
      return res.status(404).send('Post not found. Could not update.');
    }
    
    res.redirect('/index'); // Redirect to admin dashboard
  } catch (error) {
    console.error('Error updating post:', error);
    res.status(500).send('Error updating post');
  }
});

// Delete image from post
app.post('/posts/:id/delete-image', async (req, res) => {
  // Debug logging
  console.log('Delete image request received:', {
    postId: req.params.id,
    imageUrl: req.body.imageUrl
  });

  // Check if user is logged in and is an admin
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.status(403).json({ success: false, error: 'Unauthorized' });
  }
  
  try {
    const postId = req.params.id;
    const { imageUrl } = req.body;

    if (!postId || !imageUrl) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields' 
      });
    }

    // Find the post
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ 
        success: false, 
        error: 'Post not found' 
      });
    }

    // Verify the image belongs to this post
    if (post.imageUrl !== imageUrl) {
      return res.status(400).json({ 
        success: false, 
        error: 'Image does not belong to this post' 
      });
    }

    // Check if other posts are using this image
    const otherPosts = await Post.find({
      _id: { $ne: postId },
      imageUrl: imageUrl
    });

    // If no other post is using this image and it's not the default image, delete from Cloudinary
    if (otherPosts.length === 0 && !imageUrl.includes('/images/default-post.jpg')) {
      try {
        // Extract public_id from Cloudinary URL
        // Example URL: https://res.cloudinary.com/your-cloud-name/image/upload/v1234567890/robolution/posts/image123
        const urlParts = imageUrl.split('/');
        const publicId = 'robolution/posts/' + urlParts[urlParts.length - 1].split('.')[0];
        
        console.log('Attempting to delete from Cloudinary with public_id:', publicId);
        const result = await cloudinary.uploader.destroy(publicId);
        console.log('Cloudinary deletion result:', result);
      } catch (cloudinaryError) {
        console.error('Error deleting from Cloudinary:', cloudinaryError);
        // Continue with post update even if Cloudinary deletion fails
      }
    }

    // Update the post to set default image
    await Post.findByIdAndUpdate(postId, { 
      $set: { imageUrl: '/images/default-post.jpg' } 
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error in delete-image route:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete image: ' + error.message 
    });
  }
});

// Update login route to include 2FA handling and direct MongoDB access
app.post('/login', async (req, res) => {
    try {
        const { username, password, token, redirect } = req.body;
        
        console.log('Login attempt:', { username, hasToken: !!token });
        
        // DIRECT DB ACCESS: First check admin collection
        const adminUser = await db.collection('admins').findOne({ username });
        
        if (adminUser) {
            const isPasswordValid = await bcrypt.compare(password, adminUser.password);
            
            if (!isPasswordValid) {
                console.log('Invalid password for admin:', username);
                return res.json({ success: false, message: 'Invalid username or password' });
            }
            
            // Check if this admin needs to set up 2FA after password reset
            if (adminUser.needs2FASetup) {
                return res.json({ 
                    success: false, 
                    requireTwoFactor: true,
                    needs2FASetup: true,
                    message: 'Your account has been reset. Please set up two-factor authentication.',
                    username: username,
                    password: password
                });
            }
            
            // Check if 2FA is enabled
            if (adminUser.twoFactorEnabled) {
                // If no token provided but 2FA is enabled, request token
                if (!token) {
                    return res.json({ 
                        success: false, 
                        requireTwoFactor: true,
                        needs2FASetup: false,
                        message: 'Please enter your two-factor authentication code'
                    });
                }
                
                // Verify the token
                const verified = speakeasy.totp.verify({
                    secret: adminUser.twoFactorSecret,
                    encoding: 'base32',
                    token: token,
                    window: 1 // Allow 1 step before/after for time drift
                });
                
                if (!verified) {
                    // Also check backup codes
                    const isBackupCode = adminUser.backupCodes && 
                                         adminUser.backupCodes.includes(token);
                    
                    if (!isBackupCode) {
                        return res.json({ 
                            success: false, 
                            requireTwoFactor: true,
                            needs2FASetup: false,
                            message: 'Invalid two-factor code. Please try again.'
                        });
                    } else {
                        // If using backup code, remove it from the list
                        await db.collection('admins').updateOne(
                            { username: adminUser.username },
                            { $pull: { backupCodes: token } }
                        );
                    }
                }
            }
            
            // Set admin session with all necessary data
            req.session.user = {
                id: adminUser._id.toString ? adminUser._id.toString() : adminUser._id,
                username: adminUser.username,
                isAdmin: true,
                role: adminUser.role || 'admin'
            };
            
            // Force session save and wait for it
            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) {
                        console.error('Session save error:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });
            
            console.log('Admin login successful - Session saved:', {
                sessionID: req.sessionID,
                user: req.session.user,
                cookie: req.session.cookie
            });
            
            // Add localStorage configuration
            const redirectUrl = redirect || '/admin-dashboard'; // Changed from /index
            
            return res.json({ 
                success: true,
                redirectUrl: redirectUrl,
                role: adminUser.role || 'admin',
                message: 'Login successful! Welcome back, ' + adminUser.username,
                setLocalStorage: true  // Signal client to set localStorage
            });
        } else {
            // DIRECT DB ACCESS: If not an admin, check regular users collection
            const usersCollection = robolutionDb.collection('users');
            const regularUser = await usersCollection.findOne({ username });
            
            if (!regularUser) {
                console.log('User not found:', username);
                return res.json({ success: false, message: 'Invalid username or password' });
            }
            
            const isPasswordValid = await bcrypt.compare(password, regularUser.password);
            
            if (!isPasswordValid) {
                console.log('Invalid password for user:', username);
                return res.json({ success: false, message: 'Invalid username or password' });
            }
            
            // Check if this user needs to set up 2FA after password reset
            if (regularUser.needs2FASetup) {
                return res.json({ 
                    success: false, 
                    requireTwoFactor: true,
                    needs2FASetup: true,
                    message: 'Your account has been reset. Please set up two-factor authentication.',
                    username: username,
                    password: password
                });
            }
            
            // Check if 2FA is enabled for this user
            if (regularUser.twoFactorEnabled) {
                // If no token provided but 2FA is enabled, request token
                if (!token) {
                    return res.json({ 
                        success: false, 
                        requireTwoFactor: true, 
                        needs2FASetup: false,
                        message: 'Please enter your two-factor authentication code'
                    });
                }
                
                // Verify the token
                const verified = speakeasy.totp.verify({
                    secret: regularUser.twoFactorSecret,
                    encoding: 'base32',
                    token: token,
                    window: 1
                });
                
                if (!verified) {
                    // Check backup codes
                    const isBackupCode = regularUser.backupCodes && 
                                        regularUser.backupCodes.includes(token);
                    
                    if (!isBackupCode) {
                        return res.json({ 
                            success: false, 
                            requireTwoFactor: true,
                            needs2FASetup: false, 
                            message: 'Invalid two-factor code. Please try again.'
                        });
                    } else {
                        // Remove used backup code using direct MongoDB update
                        const updatedBackupCodes = regularUser.backupCodes.filter(code => code !== token);
                        await usersCollection.updateOne(
                            { _id: regularUser._id },
                            { $set: { backupCodes: updatedBackupCodes } }
                        );
                    }
                }
            }
            
            // Set regular user session
            req.session.user = {
                id: regularUser._id.toString ? regularUser._id.toString() : regularUser._id,
                username: regularUser.username,
                isAdmin: false,
                role: 'user'
            };
            
            // Force session save and wait for it
            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) {
                        console.error('Session save error:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });
            
            console.log('User login successful - Session saved:', {
                sessionID: req.sessionID,
                user: req.session.user,
                cookie: req.session.cookie
            });
            
            // Get redirect URL from request or use default
            const redirectUrl = redirect || '/user-landing'; // User redirect remains the same
            
            return res.json({ 
                success: true,
                redirectUrl: redirectUrl,
                role: 'user',
                message: 'Login successful! Welcome back, ' + regularUser.username,
                setLocalStorage: true  // Signal client to set localStorage
            });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.json({ success: false, message: 'An error occurred during login. Please try again.' });
    }
});

// Improved 2FA verification function
function verifyTwoFactorToken(user, token) {
    // For testing purposes, accept any 6-digit code
    // In production, use a proper TOTP library
    console.log('Verifying 2FA token:', token);
    
    // Simple validation - check if it's a 6-digit number
    if (/^\d{6}$/.test(token)) {
        // For testing, accept any valid 6-digit code
        // In production, replace with actual verification
        return true;
    }
    
    return false;
}

// Protected admin route
app.get('/index', (req, res) => {
    if (!req.session.user || !req.session.user.isAdmin) {
        return res.redirect('/login');
    }
    res.render('index'); // Create an admin.ejs view
});

// Admin creation route - GET
app.get('/create-admin', (req, res) => {
    res.render('create-admin');
});

// Admin creation route - POST
app.post('/create-admin', async (req, res) => {
    try {
        const { username, password, confirmPassword, adminKey } = req.body;
        
        // For debugging - remove in production
        console.log('Received admin key:', adminKey);
        
        // Verify admin creation key - use environment variable
        const ADMIN_CREATION_KEY = process.env.ADMIN_CREATION_KEY || 'your-secure-admin-key';
        
        if (adminKey.trim() !== ADMIN_CREATION_KEY.trim()) {
            return res.render('create-admin', {
                message: 'Invalid admin creation key',
                messageType: 'error'
            });
        }
        
        // Check if passwords match
        if (password !== confirmPassword) {
            return res.render('create-admin', {
                message: 'Passwords do not match',
                messageType: 'error'
            });
        }
        
        // Check if username already exists
        const existingUser = await db.collection('admins').findOne({ username });
        
        if (existingUser) {
            return res.render('create-admin', {
                message: 'Username already exists',
                messageType: 'error'
            });
        }
        
        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Generate 2FA secret
        const secret = speakeasy.generateSecret({
            name: `Robolution:${username}`
        });
        
        // Generate backup codes
        const backupCodes = Array(8).fill().map(() => 
            Math.random().toString(36).substring(2, 8).toUpperCase()
        );
        
        // Create admin user with 2FA enabled
        await db.collection('admins').insertOne({
            username,
            password: hashedPassword,
            role: 'admin',
            twoFactorSecret: secret.base32,
            twoFactorEnabled: true,
            backupCodes: backupCodes,
            createdAt: new Date()
        });
        
    } catch (error) {
        console.error('Error creating admin:', error);
        res.render('create-admin', {
            message: 'An error occurred while creating the admin account',
            messageType: 'error'
        });
    }
});

// Route to show details for a specific category for users
app.get('/user-categories/:id', async (req, res) => {
  try {
    let category;
    
    try {
      // Try standard mongoose findById
      category = await Category.findById(req.params.id);
      
      // If not found and ID seems valid
      if (!category && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
        // Try with new ObjectId
        const ObjectId = mongoose.Types.ObjectId;
        const categoryId = new ObjectId(req.params.id);
        category = await Category.findOne({ _id: categoryId });
      }
      
      // Try as string ID if still not found
      if (!category) {
        category = await Category.findOne({ _id: req.params.id });
      }
    } catch (idError) {
      console.error('Error converting category ID:', idError);
      // Continue to check if category was found
    }
    
    if (category) {
      res.render('UserViews/user-category_details', { event: category });
    } else {
      console.error('Event not found with ID:', req.params.id);
      res.status(404).send('Event not found');
    }
  } catch (error) {
    console.error('Error fetching category details:', error);
    res.status(500).send('An error occurred while fetching the category details');
  }
});

// Route to render the registration page
app.get('/registration', async (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    return res.redirect('/login?redirect=/registration');
  }
  
  try {
    // Get categories for dynamic competition options
    const categories = await Category.find();
    
    // Render the registration page with categories
    res.render('UserViews/registration', { categories });
  } catch (error) {
    console.error('Error fetching categories for registration:', error);
    res.status(500).send('Error loading registration page');
  }
});

// Route to handle registration form submission
app.post('/register', upload.single('payment'), async (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    return res.redirect('/login?redirect=/registration');
  }
  
  try {
    // Extract form data
    const {
      fullname,
      teamMembers,
      category,
      school,
      address,
      email,
      competition,
      workshop,
      other_competition,
      other_workshop,
      code,
      payment_details,
      privacy_agree
    } = req.body;

    // Validate required fields
    if (!fullname || !address || !email || !privacy_agree) {
      // Get categories for the form if validation fails
      const categories = await Category.find();
      return res.render('UserViews/registration', { 
        error: 'Please fill in all required fields',
        categories
      });
    }

    // Check if at least one workshop option is selected
    if (!workshop || workshop.length === 0) {
      const categories = await Category.find();
      return res.render('UserViews/registration', { 
        error: 'Please select at least one workshop or seminar option',
        categories
      });
    }

    // Process payment file upload
    let paymentProofUrl = '';
    if (req.file) {
      const filePath = path.join(__dirname, 'public', 'uploads', 'temp', req.file.filename);
      paymentProofUrl = await uploadToCloudinary(filePath, 'robolution/payments');
    } else {
      // Only require payment proof if at least one workshop is selected that isn't "OTHER"
      const needsPayment = Array.isArray(workshop) ? workshop.some(w => w !== 'OTHER') : workshop !== 'OTHER';
      if (needsPayment) {
        const categories = await Category.find();
        return res.render('UserViews/registration', { 
          error: 'Please upload your payment proof',
          categories
        });
      }
    }

    // Create a new registration in the database with user ID
    await Registration.create({
      userId: req.session.user.id, // Associate registration with user account
      fullname,
      teamMembers,
      category,
      school,
      address,
      email,
      competition: Array.isArray(competition) ? competition : (competition ? [competition] : []),
      workshop,
      other_competition,
      other_workshop,
      code,
      paymentProofUrl,
      payment_details
    });

    // Redirect to a success page
    res.render('UserViews/registration-success', { name: fullname });
  } catch (error) {
    console.error('Registration error:', error);
    // Get categories for the form if there's an error
    const categories = await Category.find();
    res.render('UserViews/registration', { 
      error: 'An error occurred during registration. Please try again.',
      categories
    });
  }
});

// Route to render the signup page
app.get('/signup', (req, res) => {
  res.render('UserViews/signup');
});

// Route to handle signup form submission
app.post('/signup', async (req, res) => {
  try {
    const { fullName, username, email, password, confirmPassword } = req.body;
    
    // Create an object to store form data to send back to the view
    const formData = { fullName, username, email };
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.render('UserViews/signup', { 
        error: 'Please enter a valid email address',
        formData
      });
    }
    
    // Password validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
    if (!passwordRegex.test(password)) {
      return res.render('UserViews/signup', { 
        error: 'Password must be at least 12 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character',
        formData
      });
    }
    
    // Check if passwords match
    if (password !== confirmPassword) {
      return res.render('UserViews/signup', { 
        error: 'Passwords do not match',
        formData
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render('UserViews/signup', { 
        error: 'Email already in use',
        formData
      });
    }
    
    // Check if username already exists
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.render('UserViews/signup', { 
        error: 'Username already taken',
        formData
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate 2FA secret
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `Robolution:${username}`
    });
    
    // Generate backup codes
    const backupCodes = Array(8).fill().map(() => 
      Math.random().toString(36).substring(2, 8).toUpperCase()
    );
    
    // Create user with 2FA enabled
    const user = await User.create({
      fullName,
      username,
      email,
      password: hashedPassword,
      twoFactorSecret: secret.base32,
      twoFactorEnabled: true,
      backupCodes
    });
    
    // Generate QR code
    const otpauthUrl = speakeasy.otpauthURL({
      secret: secret.base32,
      label: `Robolution:${username}`,
      issuer: 'Robolution',
      encoding: 'base32'
    });
    
    const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);
    
    // Set up session
    req.session.user = {
      _id: user._id,
      username: user.username,
      fullName: user.fullName,
      isAdmin: false
    };
    
    // Show 2FA setup page with QR code
    res.render('UserViews/setup-2fa', {
      qrCode: qrCodeUrl,
      secret: secret.base32,
      isNewUser: true,
      backupCodes: backupCodes
    });
  } catch (error) {
    console.error('Error during registration:', error);
    res.render('UserViews/signup', {
      error: 'An error occurred during registration',
      formData: { fullName, username, email }
    });
  }
});

// Route to handle user logout
app.get('/logout', (req, res) => {
  // Get original session ID to clear cache for
  const sessionID = req.sessionID;
  
  // Destroy the session
  req.session.destroy((err) => {
    if (err) {
      console.error('Error during logout:', err);
    }
    
    // Set headers to prevent browser caching
    res.set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Surrogate-Control': 'no-store'
    });
    
    // Redirect to the landing page with a script to clear localStorage and prevent back navigation
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Logging out...</title>
        <meta http-equiv="refresh" content="2;url=/user-landing">
        <style>
          body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
          }
          .logout-container {
            text-align: center;
            padding: 2rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          h1 {
            color: #4a5568;
          }
          .message {
            margin: 1rem 0;
            color: #718096;
          }
        </style>
      </head>
      <body>
        <div class="logout-container">
          <h1>Logging Out</h1>
          <p class="message">You have been successfully logged out.</p>
          <p>Redirecting you to the home page...</p>
        </div>
        
        <script>
          // Clear all localStorage data
          try {
            localStorage.removeItem('isLoggedIn');
            sessionStorage.clear();
            console.log('Login status cleared from storage');
          } catch (e) {
            console.error('Error clearing storage:', e);
          }
          
          // Clear all cookies
          document.cookie.split(';').forEach(function(c) {
            document.cookie = c.trim().split('=')[0] + '=;' + 'expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;';
          });
          
          // Clear browser history state to prevent back button navigation to cached pages
          if (window.history && window.history.pushState) {
            window.history.pushState(null, '', window.location.href);
            window.onpopstate = function() {
              window.history.pushState(null, '', window.location.href);
            };
          }
          
          // Add timestamp to redirect URL to prevent cache
          setTimeout(function() {
            window.location.href = '/user-landing?nocache=' + new Date().getTime();
          }, 2000);
        </script>
      </body>
      </html>
    `);
  });
});

// Update routes for 2FA setup and verification
app.get('/setup-2fa', async (req, res) => {
    // Check if user is logged in and is an admin
    if (!req.session.user || !req.session.user.isAdmin) {
        return res.redirect('/login');
    }
    
    try {
        // Check if 2FA is already enabled
        const admin = await db.collection('admins').findOne({ username: req.session.user.username });
        
        if (admin.twoFactorEnabled) {
            return res.redirect('/2fa-already-setup');
        }
        
        // Generate new secret
        const secret = speakeasy.generateSecret({
            name: `Robolution:${admin.username}`
        });
        
        // Store the secret temporarily in session
        req.session.twoFactorSecret = secret.base32;
        
        // Generate QR code
        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
        
        res.render('UserViews/setup-2fa', { 
            qrCode: qrCodeUrl, 
            secret: secret.base32 
        });
    } catch (error) {
        console.error('Error setting up 2FA:', error);
        res.status(500).send('Error setting up two-factor authentication');
    }
});

app.post('/verify-2fa-setup', async (req, res) => {
    // Check if user is logged in and is an admin
    if (!req.session.user || !req.session.user.isAdmin) {
        return res.redirect('/login');
    }
    
    try {
        const { token } = req.body;
        const secret = req.session.twoFactorSecret;
        
        if (!secret) {
            return res.redirect('/setup-2fa');
        }
        
        // Verify the token
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 1 // Allow 1 step before/after for time drift
        });
        
        if (!verified) {
            return res.render('UserViews/setup-2fa', {
                error: 'Invalid verification code, please try again',
                qrCode: await qrcode.toDataURL(`otpauth://totp/Robolution:${req.session.user.username}?secret=${secret}&issuer=Robolution`),
                secret: secret
            });
        }
        
        // Token is valid, enable 2FA
        await db.collection('admins').updateOne(
            { username: req.session.user.username },
            { 
                $set: { 
                    twoFactorSecret: secret,
                    twoFactorEnabled: true
                } 
            }
        );
        
        // Generate some backup codes (optional)
        const backupCodes = Array(8).fill().map(() => 
            Math.random().toString(36).substring(2, 8).toUpperCase()
        );
        
        await db.collection('admins').updateOne(
            { username: req.session.user.username },
            { $set: { backupCodes: backupCodes } }
        );
        
        // Clear the temporary secret from session
        delete req.session.twoFactorSecret;
        
        res.render('UserViews/2fa-success', { 
            message: 'Two-factor authentication has been successfully set up!',
            backupCodes: backupCodes // Display these to the user once
        });
    } catch (error) {
        console.error('Error verifying 2FA setup:', error);
        res.status(500).send('Error setting up two-factor authentication');
    }
});

app.get('/2fa-already-setup', (req, res) => {
    res.render('UserViews/2fa-already-setup', { message: 'You have already set up two-factor authentication on your account.' });
});

// Route to handle regional page requests with direct MongoDB access
app.get('/regional', async (req, res) => {
  try {
    console.log('Accessing regional page with region:', req.query.region);
    
    const region = req.query.region || 'All';
    const sortDirection = req.query.sort === 'asc' ? 1 : -1;
    
    // DIRECT COLLECTION ACCESS
    const postsCollection = robolutionDb.collection('posts');
    
    // Query to filter posts by region if a specific region is selected
    const query = region !== 'All' ? { region: region } : {};
    
    console.log('Regional query:', JSON.stringify(query));
    
    // Fetch posts based on the query and sort direction using native MongoDB
    let posts = await postsCollection.find(query).sort({ createdAt: sortDirection }).toArray();
    console.log(`Found ${posts.length} posts for region ${region}`);
    
    // Convert MongoDB documents to JavaScript objects
    posts = JSON.parse(JSON.stringify(posts));
    
    // Get unique regions for the dropdown directly from MongoDB
    const allPosts = await postsCollection.find().toArray();
    const uniqueRegions = [...new Set(allPosts.map(post => post.region).filter(region => region && region !== 'All'))].sort();
    
    res.render('UserViews/regional', { 
      posts, 
      region,
      uniqueRegions,
      sort: req.query.sort || 'desc'
    });
  } catch (error) {
    console.error('Error fetching regional posts:', error);
    res.status(500).send('An error occurred while fetching regional posts');
  }
});

// Admin regional page - similar to regional but with admin controls
app.get('/admin-regional', async (req, res) => {
  // Check if user is logged in and is an admin
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.redirect('/login');
  }
  
  try {
    const region = req.query.region || 'All';
    const sortDirection = req.query.sort === 'asc' ? 1 : -1;
    
    // Query to filter posts by region if a specific region is selected
    const query = region !== 'All' ? { region: region } : {};
    
    // Fetch posts based on the query and sort direction
    const posts = await Post.find(query).sort({ createdAt: sortDirection });
    
    // Get unique regions for the dropdown
    const allPosts = await Post.find();
    const uniqueRegions = [...new Set(allPosts.map(post => post.region).filter(region => region && region !== 'All'))].sort();
    
    res.render('admin-regional', { 
      posts, 
      region,
      uniqueRegions,
      sort: req.query.sort || 'desc'
    });
  } catch (error) {
    console.error('Error fetching admin regional posts:', error);
    res.status(500).send('An error occurred while fetching regional posts');
  }
});

// Route to show individual post details
app.get('/post/:id', async (req, res) => {
  try {
    let post;
    
    try {
      // First try standard mongoose findById
      post = await Post.findById(req.params.id);
      
      // If not found and ID seems valid
      if (!post && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
        // Try creating an ObjectId
        const ObjectId = mongoose.Types.ObjectId;
        const postId = new ObjectId(req.params.id);
        post = await Post.findOne({ _id: postId });
      }
      
      // Try as string ID if still not found
      if (!post) {
        post = await Post.findOne({ _id: req.params.id });
      }
    } catch (idError) {
      console.error('Error converting post ID:', idError);
      // Continue to check if post was found
    }
    
    if (!post) {
      console.error('Post not found with ID:', req.params.id);
      return res.status(404).send('Post not found');
    }
    
    res.render('UserViews/post-detail', { 
      post,
      req: req
    });
  } catch (error) {
    console.error('Error fetching post details:', error);
    res.status(500).send('An error occurred while fetching the post details');
  }
});

// Health check route for Render
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// API endpoint to check username availability for users
app.get('/api/check-username', async (req, res) => {
    try {
        const username = req.query.username;
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const existingUser = await User.findOne({ username: username });
        res.json({ available: !existingUser });
    } catch (error) {
        console.error('Error checking username:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// API endpoint to check username availability for admins
app.get('/api/check-admin-username', async (req, res) => {
    try {
        const username = req.query.username;
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const existingAdmin = await db.collection('admins').findOne({ username: username });
        res.json({ available: !existingAdmin });
    } catch (error) {
        console.error('Error checking admin username:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// API endpoint to check if session is still authenticated
app.get('/api/check-session', (req, res) => {
    // Set no-cache headers
    res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    });
    
    // Check if user is authenticated with detailed debugging
    const hasSession = !!req.session;
    const hasUser = hasSession && !!req.session.user;
    const hasUserId = hasUser && !!req.session.user.id;
    const isAuthenticated = hasUserId;
    
    // Log detailed session information for debugging
    console.log('Session check:', {
        url: req.url,
        sessionID: req.sessionID,
        hasSession,
        hasUser,
        hasUserId,
        isAuthenticated,
        cookies: req.headers.cookie
    });
    
    // Return authentication status with debugging info
    res.json({
        authenticated: isAuthenticated,
        timestamp: new Date().toISOString(),
        debug: {
            hasSession,
            hasUser,
            hasUserId
        }
    });
});

// Only start the server if this file is run directly (not required as a module)
if (require.main === module) {
    app.listen(port, () => {
        console.log(`Robolution site running at http://localhost:${port}`);
    });
}

// Export the app for production testing
module.exports = app;

// Delete post route
app.post('/delete-post/:id', requireAdmin, async (req, res) => {
  // Admin check is now handled by requireAdmin middleware
  // if (!req.session.user || !req.session.user.isAdmin) {
  //   return res.status(403).send('Unauthorized');
  // }
  
  try {
    const postId = req.params.id;
    const post = await Post.findById(postId);

    if (!post) {
      console.log(`[Delete Post] Post not found with ID: ${postId}`);
      return res.status(404).send('Post not found.');
    }

    // If the post has an image URL and it's a Cloudinary URL, try to delete it from Cloudinary
    if (post.imageUrl && post.imageUrl.includes('res.cloudinary.com')) {
      try {
        const parts = post.imageUrl.split('/');
        // Assumes Cloudinary folder structure like robolution/posts/filename
        const publicIdInFolder = parts.slice(parts.indexOf('robolution')).join('/'); 
        const publicId = publicIdInFolder.substring(0, publicIdInFolder.lastIndexOf('.'));
        
        console.log(`[Delete Post] Attempting to delete image from Cloudinary with public_id: ${publicId}`);
        await cloudinary.uploader.destroy(publicId);
        console.log(`[Delete Post] Successfully deleted image from Cloudinary: ${publicId}`);
      } catch (cloudinaryError) {
        console.error(`[Delete Post] Error deleting image from Cloudinary (post ID: ${postId}, image: ${post.imageUrl}):`, cloudinaryError);
        // Log the error but proceed with deleting the post from DB
      }
    } else if (post.imageUrl) {
      // Optional: Handle deletion of local images if they might still exist and are not Cloudinary URLs
      // This part depends on whether you expect any valid non-Cloudinary images.
      // For now, we'll just log if it's not a Cloudinary URL.
      console.log(`[Delete Post] Post image is not a Cloudinary URL, not attempting Cloudinary delete: ${post.imageUrl}`);
      // If you are sure these are old local files you want to attempt to delete:
      // const localFilePath = path.join(__dirname, 'public', post.imageUrl);
      // if (fs.existsSync(localFilePath)) {
      //   fs.unlink(localFilePath, (err) => {
      //     if (err) console.log('[Delete Post] Failed to delete local image:', err);
      //     else console.log('[Delete Post] Local image deleted:', localFilePath);
      //   });
      // }
    }

    await Post.findByIdAndDelete(postId);
    console.log(`[Delete Post] Successfully deleted post with ID: ${postId}`);
    
    res.redirect('/index');
  } catch (error) {
    console.error(`[Delete Post] Error deleting post with ID ${req.params.id}:`, error);
    if (error.name === 'CastError' && error.kind === 'ObjectId') {
      return res.status(400).send('Invalid Post ID format for deletion.');
    }
    res.status(500).send('Error deleting post.');
  }
});

// Add routes for user 2FA setup
app.get('/user/setup-2fa', async (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    try {
        // Check if 2FA is already enabled
        const user = await User.findById(req.session.user._id);
        
        if (user.twoFactorEnabled) {
            return res.render('UserViews/2fa-already-setup', { 
                message: 'You have already set up two-factor authentication on your account.' 
            });
        }
        
        // Generate new secret
        const secret = speakeasy.generateSecret({
            name: `Robolution:${user.username}`
        });
        
        // Store the secret temporarily in session
        req.session.twoFactorSecret = secret.base32;
        
        // Generate QR code
        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
        
        res.render('UserViews/setup-2fa', { 
            qrCode: qrCodeUrl, 
            secret: secret.base32 
        });
    } catch (error) {
        console.error('Error setting up user 2FA:', error);
        res.status(500).send('Error setting up two-factor authentication');
    }
});

app.post('/user/verify-2fa-setup', async (req, res) => {
    // Check if user is logged in
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    try {
        const { token } = req.body;
        const secret = req.session.twoFactorSecret;
        
        if (!secret) {
            return res.redirect('/user/setup-2fa');
        }
        
        // Verify the token
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 1 // Allow 1 step before/after for time drift
        });
        
        if (!verified) {
            return res.render('UserViews/setup-2fa', {
                error: 'Invalid verification code, please try again',
                qrCode: await qrcode.toDataURL(`otpauth://totp/Robolution:${req.session.user.username}?secret=${secret}&issuer=Robolution`),
                secret: secret
            });
        }
        
        // Token is valid, enable 2FA for the user
        const user = await User.findById(req.session.user._id);
        
        // Generate backup codes
        const backupCodes = Array(8).fill().map(() => 
            Math.random().toString(36).substring(2, 8).toUpperCase()
        );
        
        // Update user with 2FA details
        user.twoFactorSecret = secret;
        user.twoFactorEnabled = true;
        user.backupCodes = backupCodes;
        await user.save();
        
        // Clear the temporary secret from session
        delete req.session.twoFactorSecret;
        
        res.render('UserViews/2fa-success', { 
            message: 'Two-factor authentication has been successfully set up!',
            backupCodes: backupCodes // Display these to the user once
        });
    } catch (error) {
        console.error('Error verifying user 2FA setup:', error);
        res.status(500).send('Error setting up two-factor authentication');
    }
});

// Route to manage registrations
app.get('/manage-registrations', async (req, res) => {
  try {
    // Get filter parameters
    const category = req.query.category || 'all';
    const workshop = req.query.workshop || 'all';
    const search = req.query.search || '';
    const payment = req.query.payment || 'all';
    const verified = req.query.verified || 'all';
    
    // Build the query
    let query = {};
    
    // Apply category filter
    if (category !== 'all') {
      query.category = category;
    }
    
    // Apply workshop filter
    if (workshop !== 'all') {
      query.workshop = workshop;
    }
    
    // Apply search filter
    if (search) {
      query.$or = [
        { fullname: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { school: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Apply payment filter
    if (payment === 'paid') {
      query.paymentProofUrl = { $ne: null, $ne: '' };
    } else if (payment === 'unpaid') {
      query.$or = [
        { paymentProofUrl: null },
        { paymentProofUrl: '' }
      ];
    }
    
    // Apply verification filter
    if (verified === 'verified') {
      query.verified = true;
      query.denied = { $ne: true }; // Ensure not denied
    } else if (verified === 'unverified') {
      query.verified = { $ne: true };
      query.denied = { $ne: true }; // Ensure not denied
    } else if (verified === 'denied') {
      query.denied = true;
    }
    
    // Fetch registrations based on filters
    const registrations = await Registration.find(query).sort({ registeredAt: -1 });
    
    // Get all posts for the regional dropdown
    const posts = await Post.find();
    
    // Render the page with data
    res.render('manage-registrations', {
      registrations,
      posts,
      category,
      workshop,
      search,
      payment,
      verified
    });
  } catch (error) {
    console.error('Error fetching registrations:', error);
    res.status(500).send('An error occurred while fetching registrations');
  }
});

// Route to verify a registration
app.get('/registration/verify/:id', async (req, res) => {
  try {
    await Registration.findByIdAndUpdate(req.params.id, {
      verified: true,
      verifiedBy: req.session.user.username,
      verifiedAt: new Date()
    });
    
    res.redirect('/manage-registrations?verified=true');
  } catch (error) {
    console.error('Error verifying registration:', error);
    res.status(500).send('An error occurred while verifying the registration');
  }
});

// Route to show edit registration form with direct MongoDB access
app.get('/registration/edit/:id', async (req, res) => {
  try {
    console.log('Accessing registration for edit with ID:', req.params.id);
    
    // DIRECT COLLECTION ACCESS
    const registrationsCollection = robolutionDb.collection('registrations');
    
    // Try multiple query approaches
    let registration = null;
    
    // 1. Try direct string ID lookup
    registration = await registrationsCollection.findOne({ _id: req.params.id });
    console.log('Direct string ID lookup result:', registration ? 'Found' : 'Not found');
    
    // 2. Try ObjectID lookup if available
    if (!registration && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        registration = await registrationsCollection.findOne({ _id: new ObjectId(req.params.id) });
        console.log('ObjectId lookup result:', registration ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by email or fullname if still not found
    if (!registration) {
      registration = await registrationsCollection.findOne({ 
        $or: [
          { email: { $regex: new RegExp(req.params.id, 'i') } },
          { fullname: { $regex: new RegExp(req.params.id, 'i') } }
        ] 
      });
      console.log('Email/Name search result:', registration ? 'Found' : 'Not found');
    }
    
    if (!registration) {
      // Log the full database structure if still not found
      console.log('Registration still not found, checking database structure...');
      
      // Get collection structure
      const registrationSample = await registrationsCollection.find().limit(1).toArray();
      console.log('Sample registration structure:', JSON.stringify(registrationSample, null, 2));
      
      console.error('Registration not found with ID:', req.params.id);
      return res.status(404).send('Registration not found');
    }
    
    // Convert MongoDB document to a JavaScript object
    const registrationObject = JSON.parse(JSON.stringify(registration));
    
    res.render('edit-registration', { 
      registration: registrationObject, 
      user: req.session.user 
    });
  } catch (error) {
    console.error('Error fetching registration for edit:', error);
    res.status(500).send('An error occurred while fetching registration details');
  }
});

// Route to handle registration update
app.post('/registration/edit/:id', async (req, res) => {
  try {
    const {
      fullname, teamMembers, category, school, address, email,
      workshop, other_workshop, competition, other_competition,
      code, payment_details, verified
    } = req.body;
    
    // Prepare update data
    const updateData = {
      fullname,
      teamMembers,
      category,
      school,
      address,
      email,
      workshop,
      other_workshop,
      code,
      payment_details,
      // Convert competition to array if it's a single value or keep as is if already an array
      competition: Array.isArray(competition) ? competition : (competition ? [competition] : []),
      other_competition,
      // Handle verified status
      verified: verified === 'on'
    };
    
    // Update the registration
    await Registration.findByIdAndUpdate(req.params.id, updateData);
    
    res.redirect('/registration/' + req.params.id);
  } catch (error) {
    console.error('Error updating registration:', error);
    res.status(500).send('An error occurred while updating the registration');
  }
});

// Route to delete a registration
app.get('/registration/delete/:id', async (req, res) => {
  try {
    // Check if user is logged in and is an admin
    if (!req.session.user || !req.session.user.isAdmin) {
      return res.redirect('/login');
    }
    
    const registration = await Registration.findById(req.params.id);
    
    if (!registration) {
      return res.status(404).send('Registration not found');
    }
    
    // Delete payment proof from Cloudinary if exists
    if (registration.paymentProofUrl && registration.paymentProofUrl.includes('cloudinary')) {
      try {
        // Extract public_id from Cloudinary URL
        const urlParts = registration.paymentProofUrl.split('/');
        const publicId = 'robolution/payments/' + urlParts[urlParts.length - 1].split('.')[0];
        
        console.log('Attempting to delete payment proof from Cloudinary:', publicId);
        await cloudinary.uploader.destroy(publicId);
      } catch (cloudinaryError) {
        console.error('Error deleting payment proof from Cloudinary:', cloudinaryError);
        // Continue with registration deletion even if Cloudinary deletion fails
      }
    }
    
    // Delete the registration
    await Registration.findByIdAndDelete(req.params.id);
    
    res.redirect('/manage-registrations?deleted=true');
  } catch (error) {
    console.error('Error deleting registration:', error);
    res.status(500).send('An error occurred while deleting the registration');
  }
});

// Route to view individual registration details
app.get('/registration/:id', async (req, res) => {
  try {
    let registration = null;
    
    // Try multiple methods to find the registration
    try {
      // First try standard mongoose findById
      registration = await Registration.findById(req.params.id);
      
      // If not found and ID seems to be a valid MongoDB ObjectId string
      if (!registration && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
        // Try with new ObjectId
        const ObjectId = mongoose.Types.ObjectId;
        const regId = new ObjectId(req.params.id);
        registration = await Registration.findOne({ _id: regId });
      }
      
      // Try as string ID if still not found
      if (!registration) {
        registration = await Registration.findOne({ _id: req.params.id });
      }
    } catch (idError) {
      console.error('Error looking up registration:', idError);
    }
    
    if (!registration) {
      console.error('Registration not found with ID:', req.params.id);
      return res.status(404).send('Registration not found');
    }
    
    res.render('registration-detail', { 
      registration, 
      user: req.session.user 
    });
  } catch (error) {
    console.error('Error fetching registration details:', error);
    res.status(500).send('An error occurred while fetching registration details');
  }
});

// ====== User Account Management Routes ======

// Route to view all user accounts
app.get('/manage-accounts', requireAdmin, async (req, res) => {
  try {
    const isDashboard = req.query.dashboard === 'true';
    // Get query parameters for filtering
    const search = req.query.search || '';
    const filter2FA = req.query.filter2FA || '';
    const adminRole = req.query.adminRole || '';
    
    // Build queries for admins
    let adminQuery = {};
    if (search) {
      adminQuery.username = { $regex: search, $options: 'i' };
    }
    if (filter2FA === 'enabled') {
      adminQuery.twoFactorEnabled = true;
    } else if (filter2FA === 'disabled') {
      adminQuery.twoFactorEnabled = { $ne: true };
    }
    if (adminRole && adminRole !== 'user') {
      adminQuery.role = adminRole;
    }
    
    // Get admin accounts from adminDB with filters
    const adminAccounts = adminRole === 'user' ? [] : await db.collection('admins').find(adminQuery).toArray();
    
    // Build queries for users
    let userQuery = {};
    if (search) {
      userQuery.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { fullName: { $regex: search, $options: 'i' } }
      ];
    }
    if (filter2FA === 'enabled') {
      userQuery.twoFactorEnabled = true;
    } else if (filter2FA === 'disabled') {
      userQuery.twoFactorEnabled = { $ne: true };
    }
    
    // Get regular user accounts with filters
    const regularUsers = adminRole !== '' && adminRole !== 'user' ? [] : await User.find(userQuery).sort({ createdAt: -1 });
    
    res.render('manage-accounts', {
      admins: adminAccounts,
      users: regularUsers,
      user: req.session.user,
      search: search,
      filter2FA: filter2FA,
      adminRole: adminRole,
      dashboard: isDashboard // Pass dashboard status to template
    });
  } catch (error) {
    console.error('Error fetching accounts:', error);
    res.status(500).send('An error occurred while fetching account information');
  }
});

// Route to edit admin account
app.get('/account/admin/edit/:id', requireAdmin, async (req, res) => {
  try {
    const isDashboard = req.query.dashboard === 'true';
    console.log('Accessing admin account with ID:', req.params.id);
    
    let admin = null;
    
    // Try multiple methods to find the admin
    try {
      // First try direct lookup with MongoDB driver
      const ObjectId = require('mongodb').ObjectId;
      if (req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
        const adminId = new ObjectId(req.params.id);
        admin = await db.collection('admins').findOne({ _id: adminId });
      }
      
      // If not found, try as string ID
      if (!admin) {
        admin = await db.collection('admins').findOne({ _id: req.params.id });
      }
      
      // Try by username if still not found
      if (!admin) {
        admin = await db.collection('admins').findOne({ username: req.params.id });
      }
    } catch (idError) {
      console.error('Error looking up admin:', idError);
    }
    
    if (!admin) {
      console.error('Admin account not found with ID:', req.params.id);
      return res.status(404).send('Admin account not found');
    }
    
    // Get unique regions for the dropdown menu
    const uniqueRegions = await Post.distinct('region');
    
    res.render('edit-admin', {
      admin,
      user: req.session.user,
      uniqueRegions,
      dashboard: isDashboard // Pass dashboard status
    });
  } catch (error) {
    console.error('Error fetching admin account:', error);
    res.status(500).send('An error occurred while fetching account information');
  }
});

// Route to handle admin account updates
app.post('/account/admin/edit/:id', requireAdmin, async (req, res) => {
  try {
    // Convert string ID to ObjectId
    const ObjectId = require('mongodb').ObjectId;
    const adminId = new ObjectId(req.params.id);
    
    const { username, role, resetPassword } = req.body;
    
    // Prepare update data
    const updateData = {
      username,
      role: role || 'admin'
    };
    
    // If reset password flag is set, hash a new default password
    if (resetPassword === 'on') {
      const defaultPassword = 'Robolution@2023'; // Default password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(defaultPassword, saltRounds);
      updateData.password = hashedPassword;
    }
    
    // Update the admin account
    await db.collection('admins').updateOne(
      { _id: adminId },
      { $set: updateData }
    );
    
    res.redirect('/manage-accounts');
  } catch (error) {
    console.error('Error updating admin account:', error);
    res.status(500).send('An error occurred while updating the account');
  }
});

// Route to edit regular user account
app.get('/account/user/edit/:id', requireAdmin, async (req, res) => {
  try {
    let user = null;
    
    // Try multiple methods to find the user
    try {
      // First try standard mongoose findById
      user = await User.findById(req.params.id);
      
      // If not found and ID seems to be a valid MongoDB ObjectId string
      if (!user && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
        // Try with new ObjectId
        const ObjectId = mongoose.Types.ObjectId;
        const userId = new ObjectId(req.params.id);
        user = await User.findOne({ _id: userId });
      }
      
      // Try as string ID if still not found
      if (!user) {
        user = await User.findOne({ _id: req.params.id });
      }
      
      // Try by username if still not found
      if (!user) {
        user = await User.findOne({ username: req.params.id });
      }
    } catch (idError) {
      console.error('Error looking up user account:', idError);
    }
    
    if (!user) {
      console.error('User account not found with ID:', req.params.id);
      return res.status(404).send('User account not found');
    }
    
    // Get unique regions for the dropdown menu
    const uniqueRegions = await Post.distinct('region');
    
    res.render('edit-user', {
      userAccount: user,
      currentUser: req.session.user,
      uniqueRegions
    });
  } catch (error) {
    console.error('Error fetching user account:', error);
    res.status(500).send('An error occurred while fetching account information');
  }
});

// Route to handle user account updates
app.post('/account/user/edit/:id', requireAdmin, async (req, res) => {
  try {
    const { username, fullName, email, resetPassword, twoFactorEnabled } = req.body;
    
    // Convert string ID to ObjectId safely
    let userId;
    try {
      const ObjectId = mongoose.Types.ObjectId;
      userId = new ObjectId(req.params.id);
    } catch (idError) {
      console.error('Failed to convert user ID to ObjectId:', idError);
      userId = req.params.id; // Fallback to string ID
    }
    
    // Prepare update data
    const updateData = {
      username,
      fullName,
      email,
      twoFactorEnabled: twoFactorEnabled === 'on'
    };
    
    // If reset password flag is set, hash a new default password
    if (resetPassword === 'on') {
      const defaultPassword = 'Robolution@2023'; // Default password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(defaultPassword, saltRounds);
      updateData.password = hashedPassword;
    }
    
    // Find user first to ensure it exists
    const user = await User.findById(userId);
    
    if (!user) {
      console.error(`User not found with ID ${req.params.id}`);
      req.flash('error', 'User account not found');
      return res.redirect('/manage-accounts');
    }
    
    // Update the user account
    await User.findByIdAndUpdate(userId, updateData);
    
    req.flash('success', `User account ${username} updated successfully`);
    res.redirect('/manage-accounts');
  } catch (error) {
    console.error('Error updating user account:', error);
    req.flash('error', 'An error occurred while updating the account');
    res.redirect('/manage-accounts');
  }
});

// Admin User Profile Management Routes
// Route to view all user profiles with search capability
app.get('/admin/user-profiles', requireAdmin, async (req, res) => {
  try {
    const isDashboard = req.query.dashboard === 'true';
    const search = req.query.search || '';
    let query = {};
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { school: { $regex: search, $options: 'i' } }
      ];
    }
    const users = await User.find(query).sort({ createdAt: -1 });
    const posts = await Post.find({}); // For uniqueRegions in header/sidebar if needed
    const uniqueRegions = [...new Set(posts.filter(post => post.region && post.region !== 'All').map(post => post.region))].sort();

    res.render('admin-user-profiles', {
      users,
      search,
      user: req.session.user,
      uniqueRegions,
      dashboard: isDashboard
    });
  } catch (error) {
    console.error('Error fetching user profiles:', error);
    res.status(500).send('Error fetching user profiles');
  }
});

// Route to view specific user profile as admin
app.get('/admin/user-profiles/:id', requireAdmin, async (req, res) => {
  try {
    const isDashboard = req.query.dashboard === 'true';
    let userProfile = null;
    // Using a more robust findById approach
    const usersCollection = robolutionDb.collection('users');
    const userId = req.params.id;

    if (userId.match(/^[0-9a-fA-F]{24}$/)) {
        userProfile = await usersCollection.findOne({ _id: new ObjectId(userId) });
    } else {
        userProfile = await usersCollection.findOne({ _id: userId });
    }
    if (!userProfile) {
        userProfile = await usersCollection.findOne({ username: userId });
    }

    if (!userProfile) {
      req.flash('error', 'User not found.');
      return res.redirect('/admin/user-profiles' + (isDashboard ? '?dashboard=true' : ''));
    }

    let age = null;
    if (userProfile.birthDate && userProfile.birthDate.month && userProfile.birthDate.year) {
      const birthDate = new Date(userProfile.birthDate.year, userProfile.birthDate.month - 1);
      const today = new Date();
      age = today.getFullYear() - birthDate.getFullYear();
      const m = today.getMonth() - birthDate.getMonth();
      if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
        age--;
      }
    }
    const posts = await Post.find({}); // For uniqueRegions in header/sidebar if needed
    const uniqueRegions = [...new Set(posts.filter(post => post.region && post.region !== 'All').map(post => post.region))].sort();

    res.render('admin-view-user-profile', {
      userProfile,
      age,
      profilePicture: userProfile.profilePicture || '/images/default-profile.jpg',
      user: req.session.user,
      uniqueRegions,
      dashboard: isDashboard
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).send('Error fetching user profile');
  }
});

// Route to edit user profile as admin
app.get('/admin/user-profiles/:id/edit', requireAdmin, async (req, res) => {
  try {
    let userProfile = null;
    
    // Try multiple methods to find the user
    try {
      // First try standard mongoose findById
      userProfile = await User.findById(req.params.id);
      
      // If not found and ID seems to be a valid MongoDB ObjectId string
      if (!userProfile && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
        // Try with new ObjectId
        const ObjectId = mongoose.Types.ObjectId;
        const userId = new ObjectId(req.params.id);
        userProfile = await User.findOne({ _id: userId });
      }
      
      // Try as string ID if still not found
      if (!userProfile) {
        userProfile = await User.findOne({ _id: req.params.id });
      }
      
      // Try by username if still not found
      if (!userProfile) {
        userProfile = await User.findOne({ username: req.params.id });
      }
    } catch (idError) {
      console.error('Error looking up user profile:', idError);
    }
    
    if (!userProfile) {
      console.error('User not found with ID:', req.params.id);
      return res.status(404).send('User not found');
    }
    
    // Get unique regions for the dropdown menu
    const uniqueRegions = await Post.distinct('region');
    
    res.render('admin-edit-user-profile', {
      userProfile,
      user: req.session.user,
      uniqueRegions
    });
  } catch (error) {
    console.error('Error fetching user profile for edit:', error);
    res.status(500).send('Error fetching user profile');
  }
});

// API to update user profile as admin
app.post('/admin/user-profiles/:id/update', requireAdmin, upload.single('profilePicture'), async (req, res) => {
  try {
    const { fullName, email, birthMonth, birthYear, school, address } = req.body;
    
    // Convert string ID to ObjectId safely
    let userId;
    try {
      const ObjectId = mongoose.Types.ObjectId;
      userId = new ObjectId(req.params.id);
    } catch (idError) {
      console.error('Failed to convert user ID to ObjectId:', idError);
      userId = req.params.id; // Fallback to string ID
    }
    
    // Try to find user with multiple methods
    let userProfile = await User.findById(userId);
    
    // If not found and ID seems to be a valid MongoDB ObjectId string
    if (!userProfile && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      console.log('User not found by ID, trying alternative lookup methods');
      
      // Try to find by string ID directly
      userProfile = await User.findOne({ _id: req.params.id });
    }
    
    if (!userProfile) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Update fields
    if (fullName) userProfile.fullName = fullName;
    if (email) userProfile.email = email;
    
    // Update birth date
    if (birthMonth && birthYear) {
      userProfile.birthDate = {
        month: parseInt(birthMonth),
        year: parseInt(birthYear)
      };
    }
    
    if (school !== undefined) userProfile.school = school;
    if (address !== undefined) userProfile.address = address;
    
    // Handle profile picture upload
    if (req.file) {
      try {
        const filePath = req.file.path;
        const result = await uploadToCloudinary(filePath, 'robolution/profiles');
        userProfile.profilePicture = result;
      } catch (uploadError) {
        console.error('Error uploading to Cloudinary:', uploadError);
        return res.status(500).json({ 
          success: false, 
          message: 'Error uploading profile picture' 
        });
      }
    }
    
    await userProfile.save();
    
    // If it's an AJAX request, send JSON response
    if (req.xhr || req.headers.accept.includes('json')) {
      res.json({ success: true, message: 'Profile updated successfully' });
    } else {
      // Otherwise redirect to view profile page
      res.redirect('/admin/user-profiles/' + req.params.id);
    }
  } catch (error) {
    console.error('Error updating user profile:', error);
    
    // If it's an AJAX request, send JSON response
    if (req.xhr || req.headers.accept.includes('json')) {
      res.status(500).json({ success: false, message: 'Error updating profile' });
    } else {
      res.status(500).send('An error occurred while updating the profile');
    }
  }
});

// Route to delete admin account
app.get('/account/admin/delete/:id', requireAdmin, async (req, res) => {
  try {
    // Convert string ID to ObjectId
    const ObjectId = require('mongodb').ObjectId;
    const adminId = new ObjectId(req.params.id);
    
    // Check if this is the last admin account
    const adminCount = await db.collection('admins').countDocuments();
    if (adminCount <= 1) {
      return res.status(400).send('Cannot delete the last admin account');
    }
    
    // Check if the admin is trying to delete their own account
    if (req.session.user.id === req.params.id) {
      return res.status(400).send('Cannot delete your own account while logged in');
    }
    
    // Delete the admin account
    await db.collection('admins').deleteOne({ _id: adminId });
    
    res.redirect('/manage-accounts');
  } catch (error) {
    console.error('Error deleting admin account:', error);
    res.status(500).send('An error occurred while deleting the account');
  }
});

// Route to delete regular user account
app.get('/account/user/delete/:id', requireAdmin, async (req, res) => {
  try {
    // Convert string ID to ObjectId safely
    let userId;
    try {
      const ObjectId = mongoose.Types.ObjectId;
      userId = new ObjectId(req.params.id);
    } catch (idError) {
      console.error('Failed to convert user ID to ObjectId:', idError);
      userId = req.params.id; // Fallback to string ID
    }
    
    // Don't allow deleting your own account through this route
    if (req.session.user.id === req.params.id) {
      req.flash('error', 'You cannot delete your own account through this route.');
      return res.redirect('/manage-accounts');
    }
    
    // First find the user to ensure it exists
    let user = await User.findById(userId);
    
    // If not found, try alternative lookup methods
    if (!user && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      console.log('User not found by ID, trying alternative lookup methods');
      
      // Try to find by string ID directly
      user = await User.findOne({ _id: req.params.id });
    }
    
    if (!user) {
      req.flash('error', 'User account not found.');
      return res.redirect('/manage-accounts');
    }
    
    // Use the Mongoose method directly with the found user
    await User.deleteOne({ _id: user._id });
    
    req.flash('success', 'User account deleted successfully.');
    res.redirect('/manage-accounts');
  } catch (error) {
    console.error('Error deleting user account:', error);
    req.flash('error', 'An error occurred while deleting the user account.');
    res.redirect('/manage-accounts');
  }
});

// Route for 2FA confirmation page
app.get('/2fa-confirmation', async (req, res) => {
    try {
        const { username, password } = req.query;
        
        if (!username || !password) {
            return res.redirect('/login');
        }
        
        // Check if username exists and password is correct
        let user = await User.findOne({ username });
        let isAdmin = false;
        
        if (!user) {
            // Check admin collection
            user = await db.collection('admins').findOne({ username });
            if (user) {
                isAdmin = true;
            }
        }
        
        if (!user) {
            return res.redirect('/login');
        }
        
        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.redirect('/login');
        }
        
        // Generate a new secret for 2FA
        const secret = speakeasy.generateSecret({
            length: 20,
            name: `Robolution:${username}`
        });
        
        // Generate QR code
        const otpauthUrl = speakeasy.otpauthURL({
            secret: secret.base32,
            label: `Robolution:${username}`,
            issuer: 'Robolution',
            encoding: 'base32'
        });
        
        const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);
        
        // Generate backup codes
        const backupCodes = Array(8).fill().map(() => 
            Math.random().toString(36).substring(2, 8).toUpperCase()
        );
        
        // Render the confirmation page
        res.render('UserViews/2fa-confirmation', {
            username,
            password,
            qrCodeUrl,
            secret: secret.base32,
            backupCodes
        });
    } catch (error) {
        console.error('Error in 2FA confirmation page:', error);
        res.redirect('/login');
    }
});

// Route to verify and enable 2FA during login
app.post('/verify-login-2fa', async (req, res) => {
    try {
        const { username, password, token, secret } = req.body;
        
        if (!username || !password || !token || !secret) {
            return res.redirect('/login');
        }
        
        // Verify the token against the secret
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 1
        });
        
        if (!verified) {
            return res.render('UserViews/2fa-confirmation', {
                username,
                password,
                qrCodeUrl: await qrcode.toDataURL(speakeasy.otpauthURL({
                    secret: secret,
                    label: `Robolution:${username}`,
                    issuer: 'Robolution',
                    encoding: 'base32'
                })),
                secret,
                error: 'Invalid verification code. Please try again.'
            });
        }
        
        // Generate backup codes
        const backupCodes = Array(8).fill().map(() => 
            Math.random().toString(36).substring(2, 8).toUpperCase()
        );
        
        // Save the 2FA secret and enable 2FA
        let user = await User.findOne({ username });
        let isAdmin = false;
        
        if (user) {
            // Update user
            user.twoFactorSecret = secret;
            user.twoFactorEnabled = true;
            user.backupCodes = backupCodes;
            user.needs2FASetup = false; // Clear the flag
            await user.save();
        } else {
            // Check admin collection
            const adminUser = await db.collection('admins').findOne({ username });
            if (adminUser) {
                // Update admin
                await db.collection('admins').updateOne(
                    { username },
                    { 
                        $set: {
                            twoFactorSecret: secret,
                            twoFactorEnabled: true,
                            backupCodes,
                            needs2FASetup: false // Clear the flag
                        }
                    }
                );
                isAdmin = true;
            } else {
                return res.redirect('/login');
            }
        }
        
        // Log the user in automatically
        if (isAdmin) {
            req.session.user = {
                id: user._id.toString(),
                username: user.username,
                isAdmin: true,
                role: user.role || 'admin'
            };
        } else {
            req.session.user = {
                id: user._id.toString(),
                username: user.username,
                isAdmin: false,
                role: 'user'
            };
        }
        
        // Save session
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) {
                    console.error('Session save error:', err);
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
        
        // Render success page
        res.render('UserViews/2fa-success', {
            message: 'Two-factor authentication has been successfully set up!',
            backupCodes,
            redirectUrl: isAdmin ? '/index' : '/user-landing'
        });
    } catch (error) {
        console.error('Error verifying 2FA during login:', error);
        res.redirect('/login');
    }
});

// User profile routes
// Route to view user profile
app.get('/profile', requireLogin, async (req, res) => { // Added requireLogin
  // Check if user is logged in -- REMOVED MANUAL CHECK
  // if (!req.session || !req.session.user || !req.session.user.id) {
  //   console.log('No valid session for profile access:', { 
  //     hasSession: !!req.session,
  //     hasUser: req.session ? !!req.session.user : false,
  //     userId: req.session && req.session.user ? req.session.user.id : null
  //   });
    
  //   // Add redirect parameter so user can return to profile page after logging in
  //   return res.redirect('/login?redirect=/profile');
  // }
  
  try {
    console.log('Attempting to find user with ID:', req.session.user.id);
    
    let user = null;
    
    // Try multiple lookup methods for user
    try {
      // First try standard mongoose findById
      user = await User.findById(req.session.user.id);
      
      // If not found and ID seems to be a valid MongoDB ObjectId string
      if (!user && req.session.user.id.match(/^[0-9a-fA-F]{24}$/)) {
        // Try with new ObjectId
        const ObjectId = mongoose.Types.ObjectId;
        try {
          const userId = new ObjectId(req.session.user.id);
          user = await User.findOne({ _id: userId });
        } catch (objIdError) {
          console.error('Error converting user ID to ObjectId:', objIdError);
        }
      }
      
      // Try as string ID if still not found
      if (!user) {
        user = await User.findOne({ _id: req.session.user.id });
      }
      
      // Try by username if still not found
      if (!user && req.session.user.username) {
        console.log('Trying to find user by username:', req.session.user.username);
        user = await User.findOne({ username: req.session.user.username });
      }
    } catch (idError) {
      console.error('Error looking up user:', idError);
    }
    
    if (!user) {
      // User not found in database - likely due to database restore
      console.log('User not found in database but has session:', req.session.user);
      
      // Render an error page instead of redirecting to login
      return res.render('UserViews/user-error', {
        error: 'Account Not Found',
        message: 'Your user account could not be found in the database. This may be due to a recent database restore operation. Please sign up for a new account.',
        actionText: 'Sign Up',
        actionLink: '/signup',
        showLogoutButton: true
      });
    }
    
    // Calculate age from birth date if available
    let age = null;
    if (user.birthDate && user.birthDate.month && user.birthDate.year) {
      const currentDate = new Date();
      const currentMonth = currentDate.getMonth() + 1; // JavaScript months are 0-indexed
      const currentYear = currentDate.getFullYear();
      
      age = currentYear - user.birthDate.year;
      
      // If birth month is after current month, subtract 1 from age
      if (user.birthDate.month > currentMonth) {
        age--;
      }
    }
    
    // Get user's registrations with flexible ObjectId handling
    let registrations = [];
    try {
      // Try with ObjectId
      if (user._id) {
        if (typeof user._id === 'string' && user._id.match(/^[0-9a-fA-F]{24}$/)) {
          const ObjectId = mongoose.Types.ObjectId;
          try {
            const userId = new ObjectId(user._id);
            registrations = await Registration.find({ userId: userId }).sort({ registeredAt: -1 });
          } catch (err) {
            console.error('Error converting user._id to ObjectId:', err);
          }
        } else {
          // Direct query with user._id object
          registrations = await Registration.find({ userId: user._id }).sort({ registeredAt: -1 });
        }
        
        // If no registrations found, try with string ID
        if (registrations.length === 0) {
          registrations = await Registration.find({ userId: user._id.toString() }).sort({ registeredAt: -1 });
        }
      }
    } catch (regError) {
      console.error('Error fetching registrations:', regError);
    }
    
    // Render the profile page with all necessary data
    res.render('UserViews/profile', { 
      user,
      age,
      registrations,
      profilePicture: user.profilePicture || '/images/default-profile.jpg'
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).send('Error fetching user profile');
  }
});

// Route to update user profile
app.post('/profile/update', upload.single('profilePicture'), async (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  
  try {
    const { birthMonth, birthYear, school, address } = req.body;
    
    // Explicitly convert string ID to ObjectID if it's not already
    let userId;
    try {
      const ObjectId = mongoose.Types.ObjectId;
      userId = new ObjectId(req.session.user.id);
    } catch (idError) {
      console.error('Failed to convert ID to ObjectId:', idError);
      userId = req.session.user.id; // Fallback to string ID
    }
    
    // Find user - try multiple query methods
    let user = null;
    
    // First try with converted ObjectID (most reliable)
    user = await User.findById(userId);
    
    // If not found, try a direct query by username if available
    if (!user && req.session.user.username) {
      console.log('User not found by ID, trying by username:', req.session.user.username);
      user = await User.findOne({ username: req.session.user.username });
    }
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Update profile data
    if (birthMonth && birthYear) {
      user.birthDate = {
        month: parseInt(birthMonth),
        year: parseInt(birthYear)
      };
    }
    
    if (school) user.school = school;
    if (address) user.address = address;
    
    // Handle profile picture upload
    if (req.file) {
      try {
        const filePath = req.file.path;
        console.log('Uploading profile picture:', filePath);
        const result = await uploadToCloudinary(filePath, 'robolution/profiles');
        console.log('Cloudinary upload successful:', result);
        user.profilePicture = result;
      } catch (uploadError) {
        console.error('Error uploading to Cloudinary:', uploadError);
        return res.status(500).json({ 
          success: false, 
          message: 'Error uploading profile picture' 
        });
      }
    }
    
    await user.save();
    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ success: false, message: 'Error updating profile' });
  }
});

// Route to check username availability for users
app.get('/api/check-username', async (req, res) => {
    try {
        const username = req.query.username;
        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const existingUser = await User.findOne({ username: username });
        res.json({ available: !existingUser });
    } catch (error) {
        console.error('Error checking username:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Route to deny a registration
app.post('/registration/deny', async (req, res) => {
  try {
    const { registrationId, deniedReason, deniedMessage } = req.body;
    
    // Validate the required fields
    if (!registrationId || !deniedReason) {
      return res.status(400).send('Missing required fields');
    }
    
    // Update the registration
    await Registration.findByIdAndUpdate(registrationId, {
      denied: true,
      deniedReason,
      deniedMessage,
      deniedBy: req.session.user.username,
      deniedAt: new Date(),
      verified: false // Reset verified status
    });
    
    res.redirect('/manage-registrations?verified=denied');
  } catch (error) {
    console.error('Error denying registration:', error);
    res.status(500).send('An error occurred while denying the registration');
  }
});

// API route to update registration status
app.post('/registration/update-status/:id', async (req, res) => {
  try {
    const { denied } = req.body;
    const registrationId = req.params.id;
    
    // Validate registration ID
    if (!registrationId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Registration ID is required' 
      });
    }
    
    // Find the registration
    const registration = await Registration.findById(registrationId);
    
    if (!registration) {
      return res.status(404).json({ 
        success: false, 
        error: 'Registration not found' 
      });
    }
    
    // Update the registration based on the denied flag
    if (denied) {
      // This branch is for setting a registration to denied again
      await Registration.findByIdAndUpdate(registrationId, {
        denied: true
      });
    } else {
      // This branch is for changing from denied to unverified
      await Registration.findByIdAndUpdate(registrationId, {
        denied: false,
        deniedReason: null,
        deniedMessage: null,
        deniedBy: null,
        deniedAt: null
      });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating registration status:', error);
    res.status(500).json({ 
      success: false, 
      error: 'An error occurred while updating the registration status' 
    });
  }
});

// Admin password reset route
app.get('/account/admin/reset-password/:id', requireAdmin, async (req, res) => {
  try {
    const adminId = req.params.id;
    
    // Find the admin account
    const admin = await Admin.findById(adminId);
    if (!admin) {
      req.flash('error', 'Admin account not found.');
      return res.redirect('/manage-accounts');
    }
    
    // Generate a temporary password (alphanumeric, 10 characters)
    const tempPassword = Math.random().toString(36).substring(2, 12);
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(tempPassword, 10);
    
    // Update the admin's password and require 2FA setup on next login
    admin.password = hashedPassword;
    admin.twoFactorEnabled = false; // Disable 2FA
    admin.needs2FASetup = true; // Flag that user needs to set up 2FA on next login
    await admin.save();
    
    req.flash('success', `Password for ${admin.username} has been reset. Temporary password: ${tempPassword}`);
    res.redirect('/manage-accounts');
  } catch (error) {
    console.error('Error resetting admin password:', error);
    req.flash('error', 'An error occurred while resetting the admin password.');
    res.redirect('/manage-accounts');
  }
});

// User password reset route
app.get('/account/user/reset-password/:id', requireAdmin, async (req, res) => {
  try {
    // Convert string ID to ObjectId safely
    let userId;
    try {
      const ObjectId = mongoose.Types.ObjectId;
      userId = new ObjectId(req.params.id);
    } catch (idError) {
      console.error('Failed to convert user ID to ObjectId:', idError);
      userId = req.params.id; // Fallback to string ID
    }
    
    // Find the user account - try multiple methods
    let user = await User.findById(userId);
    
    // If not found and ID seems to be a valid MongoDB ObjectId string
    if (!user && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      console.log('User not found by ID, trying alternative lookup methods');
      
      // Try to find by string ID directly
      user = await User.findOne({ _id: req.params.id });
    }
    
    if (!user) {
      req.flash('error', 'User account not found.');
      return res.redirect('/manage-accounts');
    }
    
    // Generate a temporary password (alphanumeric, 10 characters)
    const tempPassword = Math.random().toString(36).substring(2, 12);
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(tempPassword, 10);
    
    // Update the user's password and require 2FA setup on next login
    user.password = hashedPassword;
    user.twoFactorEnabled = false; // Disable 2FA
    user.needs2FASetup = true; // Flag that user needs to set up 2FA on next login
    await user.save();
    
    req.flash('success', `Password for ${user.username} has been reset. Temporary password: ${tempPassword}`);
    res.redirect('/manage-accounts');
  } catch (error) {
    console.error('Error resetting user password:', error);
    req.flash('error', 'An error occurred while resetting the user password.');
    res.redirect('/manage-accounts');
  }
});

// User password change route
app.post('/account/user/change-password/:id', requireAdmin, async (req, res) => {
  try {
    // Convert string ID to ObjectId safely
    let userId;
    try {
      const ObjectId = mongoose.Types.ObjectId;
      userId = new ObjectId(req.params.id);
    } catch (idError) {
      console.error('Failed to convert user ID to ObjectId:', idError);
      userId = req.params.id; // Fallback to string ID
    }
    
    const { password, confirmPassword } = req.body;
    
    // Validate passwords
    if (!password || !confirmPassword) {
      return res.status(400).json({ success: false, message: 'Both password fields are required.' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match.' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
    }
    
    // Find the user account - try multiple methods
    let user = await User.findById(userId);
    
    // If not found and ID seems to be a valid MongoDB ObjectId string
    if (!user && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      console.log('User not found by ID, trying alternative lookup methods');
      
      // Try to find by string ID directly
      user = await User.findOne({ _id: req.params.id });
    }
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User account not found.' });
    }
    
    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Update the user's password but maintain 2FA status
    user.password = hashedPassword;
    await user.save();
    
    res.json({ success: true, message: `Password for ${user.username} has been changed successfully.` });
  } catch (error) {
    console.error('Error changing user password:', error);
    res.status(500).json({ success: false, message: 'An error occurred while changing the password.' });
  }
});

// Database backup management route
app.get('/manage-backups', requireAdmin, async (req, res) => {
  try {
    const isDashboard = req.query.dashboard === 'true';
    // Optional: Add superadmin check if only superadmins can manage backups
    if (req.session.user.role !== 'superadmin') {
        req.flash('error', 'You are not authorized to manage backups.');
        // Redirect to dashboard or another appropriate page if loaded in iframe
        if (isDashboard) {
             return res.status(403).send('Unauthorized. This content would normally redirect.'); // Or render a simple error view
        }
        return res.redirect('/admin-dashboard'); 
    }

    const client = await MongoClient.connect(process.env.MONGODB_URI);
    const db = client.db('robolution');
    const backups = await db.collection('database_backups')
      .find({})
      .sort({ timestamp: -1 })
      .toArray()
      .then(backups => backups.map(backup => ({
        name: backup.backupId,
        timestamp: backup.timestamp,
        size: backup.size ? (backup.size / (1024 * 1024)).toFixed(2) + ' MB' : '0.05 MB',
        files: backup.files || [],
        metadataUrl: backup.metadataUrl,
        _id: backup._id
      })));
    
    const posts = await Post.find({}); // For uniqueRegions in header/sidebar if needed
    const uniqueRegions = [...new Set(posts.filter(post => post.region && post.region !== 'All').map(post => post.region))].sort();

    res.render('manage-backups', {
      title: 'Manage Database Backups | Robolution Admin',
      user: req.session.user,
      backups: backups,
      moment: moment, // Pass moment for date formatting
      uniqueRegions,
      dashboard: isDashboard,
      success: req.flash ? req.flash('success') : [],
      error: req.flash ? req.flash('error') : []
    });
    await client.close();
  } catch (error) {
    console.error('Error accessing backups page:', error);
    req.flash('error', 'An error occurred while accessing database backups.');
    if (isDashboard) {
        return res.status(500).send('Error loading backup information.');
    }
    res.redirect('/admin-dashboard'); // Or appropriate error page
  }
});

// Trigger a manual backup
app.post('/trigger-backup', requireAdmin, async (req, res) => {
  try {
    const backupsDir = path.join(__dirname, 'database_backups');
    
    // Create backups directory if it doesn't exist
    if (!fs.existsSync(backupsDir)) {
      fs.mkdirSync(backupsDir, { recursive: true });
    }
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupId = `backup-${timestamp}`;
    const backupPath = path.join(backupsDir, backupId);
    
    // Create timestamp directory
    if (!fs.existsSync(backupPath)) {
      fs.mkdirSync(backupPath, { recursive: true });
    }
    
    // Get a client to the MongoDB database
    const client = await MongoClient.connect(process.env.MONGODB_URI);
    const dbName = 'robolution'; // Your database name
    const db = client.db(dbName);
    
    // Get all collections in the database
    const collections = await db.listCollections().toArray();
    
    // Store information about all files uploaded
    const uploadedFiles = [];
    
    // For each collection, export all documents to a JSON file and upload to Cloudinary
    for (const collection of collections) {
      const collectionName = collection.name;
      const documents = await db.collection(collectionName).find({}).toArray();
      
      // Save documents to a JSON file temporarily
      const collectionFile = path.join(backupPath, `${collectionName}.json`);
      fs.writeFileSync(collectionFile, JSON.stringify(documents, null, 2));
      
      // Upload the JSON file to Cloudinary
      const cloudinaryResult = await uploadToCloudinary(collectionFile, `robolution/backups/${backupId}`);
      uploadedFiles.push({
        collection: collectionName,
        url: cloudinaryResult,
        documentCount: documents.length
      });
    }
    
    // Write metadata about the backup
    const metadata = {
      timestamp: timestamp,
      date: new Date().toString(),
      databaseName: dbName,
      collections: collections.map(c => c.name),
      backupType: 'cloudinary_export',
      files: uploadedFiles,
      triggeredBy: req.session.user.username
    };
    
    // Save metadata file
    const metadataFile = path.join(backupPath, 'backup-metadata.json');
    fs.writeFileSync(metadataFile, JSON.stringify(metadata, null, 2));
    
    // Upload metadata file to Cloudinary
    const metadataUrl = await uploadToCloudinary(metadataFile, `robolution/backups/${backupId}`);
    
    // Save backup record to the database
    await db.collection('database_backups').insertOne({
      backupId,
      timestamp: new Date(),
      metadataUrl,
      files: uploadedFiles,
      size: uploadedFiles.reduce((acc, file) => acc + (file.size || 0), 0)
    });
    
    // Clean up temporary files
    try {
      fs.rm(backupPath, { recursive: true, force: true }, (err) => {
        if (err) {
          console.error(`Error cleaning up temporary backup files: ${err.message}`);
        } else {
          console.log(`Cleaned up temporary backup directory: ${backupPath}`);
        }
      });
    } catch (cleanupError) {
      console.error(`Error during backup cleanup: ${cleanupError.message}`);
    }
    
    // Close the client
    await client.close();
    
    req.flash('success', 'Database backup created successfully.');
    res.redirect('/manage-backups');
  } catch (error) {
    console.error('Error triggering backup:', error);
    req.flash('error', 'An error occurred while triggering the backup.');
    res.redirect('/manage-backups');
  }
});

// Delete a backup
app.get('/delete-backup/:name', requireAdmin, async (req, res) => {
  try {
    const backupId = req.params.name;
    if (!backupId || !backupId.startsWith('backup-')) {
      req.flash('error', 'Invalid backup name.');
      return res.redirect('/manage-backups');
    }
    
    // Connect to the database
    const client = await MongoClient.connect(process.env.MONGODB_URI);
    const db = client.db('robolution');
    
    // Find the backup record
    const backup = await db.collection('database_backups').findOne({ backupId });
    
    if (!backup) {
      req.flash('error', 'Backup not found.');
      await client.close();
      return res.redirect('/manage-backups');
    }
    
    // Delete each file from Cloudinary
    if (backup.files && backup.files.length > 0) {
      for (const file of backup.files) {
        if (file.url) {
          try {
            // Extract public_id from Cloudinary URL
            const urlParts = file.url.split('/');
            const publicId = `robolution/backups/${backupId}/${urlParts[urlParts.length - 1].split('.')[0]}`;
            
            // Delete from Cloudinary
            await cloudinary.uploader.destroy(publicId);
            console.log(`Deleted Cloudinary file: ${publicId}`);
          } catch (err) {
            console.error(`Error deleting Cloudinary file: ${err.message}`);
          }
        }
      }
    }
    
    // Delete metadata from Cloudinary if it exists
    if (backup.metadataUrl) {
      try {
        const urlParts = backup.metadataUrl.split('/');
        const publicId = `robolution/backups/${backupId}/${urlParts[urlParts.length - 1].split('.')[0]}`;
        
        await cloudinary.uploader.destroy(publicId);
        console.log(`Deleted Cloudinary metadata file: ${publicId}`);
      } catch (err) {
        console.error(`Error deleting Cloudinary metadata file: ${err.message}`);
      }
    }
    
    // Delete the backup record from the database
    await db.collection('database_backups').deleteOne({ _id: backup._id });
    
    await client.close();
    req.flash('success', 'Backup deleted successfully.');
    res.redirect('/manage-backups');
  } catch (error) {
    console.error('Error deleting backup:', error);
    req.flash('error', 'An error occurred while deleting the backup.');
    res.redirect('/manage-backups');
  }
});

// Restore from a backup
app.get('/restore-backup/:name', requireAdmin, async (req, res) => {
  try {
    const backupId = req.params.name;
    if (!backupId || !backupId.startsWith('backup-')) {
      req.flash('error', 'Invalid backup name.');
      return res.redirect('/manage-backups');
    }
    
    // Create temp directory for restoration
    const restorePath = path.join(__dirname, 'database_backups', 'restore_temp');
    if (!fs.existsSync(restorePath)) {
      fs.mkdirSync(restorePath, { recursive: true });
    }
    
    // Connect to the database to find the backup record
    const client = await MongoClient.connect(process.env.MONGODB_URI);
    const db = client.db('robolution');
    
    // Find the backup record
    const backup = await db.collection('database_backups').findOne({ backupId });
    
    if (!backup) {
      req.flash('error', 'Backup not found.');
      await client.close();
      return res.redirect('/manage-backups');
    }
    
    console.log(`Starting database restoration from backup: ${backupId}`);
    
    // Download all backup files from Cloudinary to temp directory
    if (!backup.files || backup.files.length === 0) {
      req.flash('error', 'Backup files information is missing.');
      await client.close();
      return res.redirect('/manage-backups');
    }

    // First, backup current users collection to preserve active user accounts
    console.log('Backing up current user accounts before restoration...');
    const currentUsers = await db.collection('users').find({}).toArray();
    const currentAdmins = await db.collection('admins').find({}).toArray();
    
    // Store current session user for special handling
    const currentAdminUser = req.session.user;
    
    // Create maps of existing users and admins by username for quick lookup
    const existingUsersMap = {};
    currentUsers.forEach(user => {
      if (user.username) {
        existingUsersMap[user.username] = user;
      }
    });
    
    const existingAdminsMap = {};
    currentAdmins.forEach(admin => {
      if (admin.username) {
        existingAdminsMap[admin.username] = admin;
      }
    });
    
    console.log(`Preserved ${Object.keys(existingUsersMap).length} existing user accounts and ${Object.keys(existingAdminsMap).length} admin accounts`);
    
    // Helper function to convert string IDs to ObjectIds consistently
    const processDocument = (doc) => {
      if (doc === null || typeof doc !== 'object') {
        return doc;
      }

      const newDoc = Array.isArray(doc) ? [] : {};

      for (const key in doc) {
        if (Object.prototype.hasOwnProperty.call(doc, key)) {
          const value = doc[key];

          if (typeof value === 'string' && /^[0-9a-fA-F]{24}$/.test(value)) {
            try {
              newDoc[key] = new ObjectId(value);
            } catch (e) {
              console.log(`Could not convert field ${key} value ${value} to ObjectId: ${e.message}`);
              newDoc[key] = value; // Keep original if conversion fails
            }
          } else if (value && typeof value === 'object' && value.$date && typeof value.$date === 'string') {
            newDoc[key] = new Date(value.$date);
          } else if (value && typeof value === 'object') {
            newDoc[key] = processDocument(value); // Recurse for nested objects/arrays
          } else {
            newDoc[key] = value;
          }
        }
      }
      return newDoc;
    };
    
    // Download and process each collection file
    for (const file of backup.files) {
      if (!file.url || !file.collection) {
        console.log(`[Restore] Skipping file with missing information: ${JSON.stringify(file)}`);
        continue;
      }
      
      console.log(`[Restore] Processing file: ${file.collection} from ${file.url}`); // Added log

      try {
        // Download file from Cloudinary
        const response = await axios.get(file.url, { responseType: 'text' });
        const data = await response.data;
        const collectionData = JSON.parse(data);
        const collectionName = file.collection;
        
        console.log(`[Restore] Restoring collection: ${collectionName} with ${collectionData.length} documents`);
        
        // Special handling for users and admins collections to preserve current users
        if (collectionName === 'users') {
          console.log('[Restore] Merging users with preserved accounts...');
          
          // Process documents to convert string IDs to ObjectIds where needed
          const processedData = collectionData.map(doc => { // Added logging for posts
            const processed = processDocument(doc);
            if (collectionName === 'posts' && processed.imageUrl) {
              console.log(`[Restore Post Detail] Original imageUrl from backup for post "${processed.title}": ${doc.imageUrl}`);
              console.log(`[Restore Post Detail] Processed imageUrl for post "${processed.title}": ${processed.imageUrl}`);
            }
            return processed;
          });
          
          // Drop the existing collection
          try {
            await db.collection(collectionName).drop();
            console.log(`[Restore] Dropped existing collection: ${collectionName}`);
          } catch (dropError) {
            // Collection might not exist, which is okay
            console.log(`[Restore] Collection ${collectionName} might not exist, continuing`);
          }
          
          // Merge backup users with current users (current users take precedence)
          const mergedUsers = [];
          
          // First add all backup users that don't exist in current system
          processedData.forEach(backupUser => {
            if (!backupUser.username || !existingUsersMap[backupUser.username]) {
              mergedUsers.push(backupUser);
            }
          });
          
          // Then add all current users
          Object.values(existingUsersMap).forEach(currentUser => {
            mergedUsers.push(processDocument(currentUser));
          });
          
          // Insert the merged users
          if (mergedUsers.length > 0) {
            await db.collection(collectionName).insertMany(mergedUsers);
            console.log(`[Restore] Restored ${mergedUsers.length} users with ${Object.keys(existingUsersMap).length} preserved accounts`);
          }
        } 
        // Special handling for admins collection
        else if (collectionName === 'admins') {
          console.log('[Restore] Merging admins with preserved accounts...');
          
          // Process documents to convert string IDs to ObjectIds where needed
          const processedData = collectionData.map(doc => { // Added logging for posts
            const processed = processDocument(doc);
            if (collectionName === 'posts' && processed.imageUrl) {
              console.log(`[Restore Post Detail] Original imageUrl from backup for post "${processed.title}": ${doc.imageUrl}`);
              console.log(`[Restore Post Detail] Processed imageUrl for post "${processed.title}": ${processed.imageUrl}`);
            }
            return processed;
          });
          
          // Drop the existing collection
          try {
            await db.collection(collectionName).drop();
            console.log(`[Restore] Dropped existing collection: ${collectionName}`);
          } catch (dropError) {
            // Collection might not exist, which is okay
            console.log(`[Restore] Collection ${collectionName} might not exist, continuing`);
          }
          
          // Merge backup admins with current admins (current admins take precedence)
          const mergedAdmins = [];
          
          // First add all backup admins that don't exist in current system
          processedData.forEach(backupAdmin => {
            if (!backupAdmin.username || !existingAdminsMap[backupAdmin.username]) {
              mergedAdmins.push(backupAdmin);
            }
          });
          
          // Then add all current admins
          Object.values(existingAdminsMap).forEach(currentAdmin => {
            mergedAdmins.push(processDocument(currentAdmin));
          });
          
          // Insert the merged admins
          if (mergedAdmins.length > 0) {
            await db.collection(collectionName).insertMany(mergedAdmins);
            console.log(`[Restore] Restored ${mergedAdmins.length} admins with ${Object.keys(existingAdminsMap).length} preserved accounts`);
          }
        }
        else {
          // Regular handling for other collections
          console.log(`[Restore] Performing regular restore for collection: ${collectionName}`); // Added log
          
          // Drop the existing collection to ensure clean restore
          try {
            await db.collection(collectionName).drop();
            console.log(`[Restore] Dropped existing collection: ${collectionName}`);
          } catch (dropError) {
            console.log(`[Restore] Collection ${collectionName} might not exist or drop failed (which can be OK): ${dropError.message}`);
          }
          
          // Process documents with consistent ObjectID handling
          const processedData = collectionData.map(doc => {
            const processed = processDocument(doc);
            if (collectionName === 'posts' && doc.imageUrl) { // Check original doc for imageUrl
              console.log(`[Restore Post Detail] Original imageUrl from backup for post "${doc.title}": ${doc.imageUrl}`);
              console.log(`[Restore Post Detail] Processed imageUrl for post "${processed.title}": ${processed.imageUrl}`);
            }
            return processed;
          });
          
          // Insert the backup data
          if (processedData.length > 0) {
            console.log(`[Restore] Attempting to insert ${processedData.length} documents into ${collectionName}. First doc: ${JSON.stringify(processedData[0])}`); // Added log
            await db.collection(collectionName).insertMany(processedData);
            console.log(`[Restore] Restored ${processedData.length} documents to ${collectionName}`);
          } else {
            console.log(`[Restore] No documents to insert for ${collectionName}.`); // Added log
          }
        }
      } catch (fileError) {
        console.error(`[Restore] Error processing file ${file.collection}:`, fileError.message); // Log error message
        console.error(`[Restore] Full error object for ${file.collection}:`, fileError); // Log full error object
      }
    }
    
    // Clean up temp directory
    try {
      fs.rm(restorePath, { recursive: true, force: true }, (err) => {
        if (err) {
          console.error(`Error cleaning up temp restore directory: ${err.message}`);
        } else {
          console.log(`Cleaned up temp restore directory`);
        }
      });
    } catch (cleanupError) {
      console.error(`Error during restore cleanup: ${cleanupError.message}`);
    }
    
    // Refresh Mongoose connection to ensure it's using updated database
    try {
      console.log('Refreshing Mongoose connection after restore...');
      await mongoose.disconnect();
      await mongoose.connect(process.env.MONGODB_URI, { dbName: 'robolution' });
      console.log('Mongoose connection refreshed');
    } catch (reconnectError) {
      console.error('Error refreshing Mongoose connection:', reconnectError);
    }
    
    // Restore session for current admin user
    if (currentAdminUser) {
      req.session.user = currentAdminUser;
      await new Promise((resolve, reject) => {
        req.session.save((err) => {
          if (err) {
            console.error('Error saving session after restore:', err);
            reject(err);
          } else {
            resolve();
          }
        });
      });
      console.log('Admin session preserved after restore');
    }
    
    // Close the client
    await client.close();
    
    // Add a message about potentially affected user sessions
    req.flash('success', `Database successfully restored from backup: ${backupId}. Active user sessions may need to log in again.`);
    res.redirect('/manage-backups');
  } catch (error) {
    console.error('Error restoring backup:', error);
    req.flash('error', `Error during database restoration: ${error.message}`);
    res.redirect('/manage-backups');
  }
});

// Helper function to get directory size
function getDirSize(dirPath) {
  let size = 0;
  
  try {
    const files = fs.readdirSync(dirPath);
    
    for (const file of files) {
      const filePath = path.join(dirPath, file);
      const stats = fs.statSync(filePath);
      
      if (stats.isDirectory()) {
        size += getDirSize(filePath);
      } else {
        size += stats.size;
      }
    }
  } catch (error) {
    console.error(`Error calculating directory size: ${error.message}`);
  }
  
  // Convert to MB with 2 decimal places
  return (size / (1024 * 1024)).toFixed(2) + ' MB';
}

// Route to handle user password changes from profile page
app.post('/profile/change-password', async (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'New passwords do not match' });
    }
    
    // Find user
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password
    user.password = hashedPassword;
    await user.save();
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ success: false, message: 'An error occurred while changing password' });
  }
});

// Add this helper function near the top of the file, after the imports but before the routes
// Flexible ID lookup helper function for MongoDB
async function findDocumentById(collection, id, options = {}) {
  try {
    const { alternativeFields = [] } = options;
    const ObjectId = require('mongodb').ObjectId;
    
    // Array to store query conditions
    const queryConditions = [];
    
    // Try as ObjectId
    if (typeof id === 'string' && id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const objId = new ObjectId(id);
        queryConditions.push({ _id: objId });
      } catch (err) {
        console.log(`Could not convert ${id} to ObjectId:`, err.message);
      }
    }
    
    // Try as plain string ID
    if (typeof id === 'string') {
      queryConditions.push({ _id: id });
    }
    
    // Add any alternative field lookups
    for (const field of alternativeFields) {
      if (field && id) {
        queryConditions.push({ [field]: id });
      }
    }
    
    // If we have any query conditions, search for the document
    if (queryConditions.length > 0) {
      const query = queryConditions.length === 1 
        ? queryConditions[0] 
        : { $or: queryConditions };
      
      console.log('Searching with query:', JSON.stringify(query));
      return await collection.findOne(query);
    }
    
    return null;
  } catch (error) {
    console.error('Error in findDocumentById:', error);
    return null;
  }
}

// Add this right after the mongoose connection setup but before setting up routes
// -------- Add database connection monitoring and recovery --------

// Track connection state
let isMongooseConnected = false;
let connectionCheckInterval;

// Monitor mongoose connection
mongoose.connection.on('connected', () => {
  console.log('Mongoose connection established');
  isMongooseConnected = true;
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose disconnected');
  isMongooseConnected = false;
});

mongoose.connection.on('error', (err) => {
  console.error('Mongoose connection error:', err);
  isMongooseConnected = false;
});

// Function to check and reconnect Mongoose if needed
const checkAndReconnectMongoose = async () => {
  if (!isMongooseConnected) {
    try {
      console.log('Attempting to reconnect Mongoose...');
      await mongoose.disconnect(); // Ensure clean disconnect first
      await mongoose.connect(uri, { dbName: 'robolution' });
      console.log('Mongoose reconnection successful');
    } catch (error) {
      console.error('Mongoose reconnection failed:', error);
    }
  }
};

// Start connection monitoring
connectionCheckInterval = setInterval(checkAndReconnectMongoose, 30000); // Check every 30 seconds

// Enhance the findDocumentById function for more robust lookups
async function findDocumentById(collection, id, options = {}) {
  try {
    const { alternativeFields = [], modelType = null } = options;
    const ObjectId = require('mongodb').ObjectId;
    
    console.log(`Attempting to find document in ${collection.collectionName || 'collection'} with ID: ${id}`);
    
    // If we were passed a mongoose model instead of a collection
    if (modelType) {
      // Try direct mongoose findById first (most reliable if ID format matches)
      try {
        const doc = await modelType.findById(id);
        if (doc) {
          console.log(`Found document using mongoose findById`);
          return doc;
        }
      } catch (err) {
        console.log(`Mongoose findById failed:`, err.message);
      }
    }
    
    // Array to store query conditions
    const queryConditions = [];
    
    // Try as ObjectId
    if (typeof id === 'string' && id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const objId = new ObjectId(id);
        queryConditions.push({ _id: objId });
      } catch (err) {
        console.log(`Could not convert ${id} to ObjectId:`, err.message);
      }
    }
    
    // Try as plain string ID
    if (typeof id === 'string') {
      queryConditions.push({ _id: id });
    }
    
    // Add any alternative field lookups
    for (const field of alternativeFields) {
      if (field && id) {
        queryConditions.push({ [field]: id });
      }
    }
    
    // If we have any query conditions, search for the document
    if (queryConditions.length > 0) {
      const query = queryConditions.length === 1 
        ? queryConditions[0] 
        : { $or: queryConditions };
      
      console.log('Searching with query:', JSON.stringify(query));
      
      // If we have a mongoose model, use it
      if (modelType) {
        const doc = await modelType.findOne(query);
        if (doc) {
          console.log(`Found document using mongoose findOne with query`);
          return doc;
        }
      }
      
      // Otherwise use the MongoDB native driver collection
      const doc = await collection.findOne(query);
      if (doc) {
        console.log(`Found document using MongoDB native findOne`);
        return doc;
      } else {
        console.log(`No document found with any method for ID: ${id}`);
      }
    }
    
    // Document truly not found
    console.log(`Document not found in ${collection.collectionName || 'collection'} with ID: ${id}`);
    return null;
  } catch (error) {
    console.error('Error in findDocumentById:', error);
    return null;
  }
}

// Update Admin model to use both model and collection approaches
const Admin = {
  findById: async function(id) {
    try {
      if (!db) {
        throw new Error('Database not initialized');
      }
      // First try to find in adminDB
      const adminUser = await findDocumentById(db.collection('admins'), id, { 
        alternativeFields: ['username'] 
      });
      
      if (adminUser) return adminUser;
      
      // If not found and robolutionDb is available, try there too
      if (robolutionDb) {
        return await findDocumentById(robolutionDb.collection('admins'), id, {
          alternativeFields: ['username']
        });
      }
      
      return null;
    } catch (error) {
      console.error('Error in Admin.findById:', error);
      throw error;
    }
  }
};

// Update the route to show individual post details with direct MongoDB collection access
app.get('/post/:id', async (req, res) => {
  try {
    console.log('Accessing post with ID:', req.params.id);
    
    // DIRECT COLLECTION ACCESS - bypass Mongoose completely
    // This is the most direct and reliable way to access the data
    const postsCollection = robolutionDb.collection('posts');
    
    // Try multiple query approaches
    let post = null;
    
    // 1. Try direct string ID lookup
    post = await postsCollection.findOne({ _id: req.params.id });
    console.log('Direct string ID lookup result:', post ? 'Found' : 'Not found');
    
    // 2. Try ObjectID lookup if available
    if (!post && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        post = await postsCollection.findOne({ _id: new ObjectId(req.params.id) });
        console.log('ObjectId lookup result:', post ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by title if still not found
    if (!post) {
      // Search by title as a last resort
      post = await postsCollection.findOne({ title: { $regex: new RegExp(req.params.id, 'i') } });
      console.log('Title search result:', post ? 'Found' : 'Not found');
    }
    
    // Log the full database structure if still not found
    if (!post) {
      console.log('Post still not found, checking database structure...');
      
      // Get collection structure
      const postsSample = await postsCollection.find().limit(1).toArray();
      console.log('Sample post structure:', JSON.stringify(postsSample, null, 2));
      
      console.error('Post not found with ID:', req.params.id);
      return res.status(404).send('Post not found');
    }
    
    // Convert MongoDB document to a JavaScript object 
    // This ensures compatibility with templates and avoids MongoDB document restrictions
    const postObject = JSON.parse(JSON.stringify(post));
    
    res.render('UserViews/post-detail', { 
      post: postObject,
      req: req
    });
  } catch (error) {
    console.error('Error fetching post details:', error);
    res.status(500).send('An error occurred while fetching the post details');
  }
});

// Update route to show edit post page with direct MongoDB access
app.get('/edit-post/:id', requireAdmin, async (req, res) => {
  // Check if user is logged in and is an admin
  if (!req.session.user || !req.session.user.isAdmin) {
    return res.redirect('/login');
  }

  try {
    console.log('Accessing post for editing, ID:', req.params.id);
    
    // DIRECT COLLECTION ACCESS - bypass Mongoose completely
    const postsCollection = robolutionDb.collection('posts');
    
    // Get all posts for regions dropdown using native MongoDB
    const posts = await postsCollection.find().toArray();

    // Try multiple query approaches to find the specific post
    let post = null;
    
    // 1. Try direct string ID lookup
    post = await postsCollection.findOne({ _id: req.params.id });
    console.log('Direct string ID lookup result:', post ? 'Found' : 'Not found');
    
    // 2. Try ObjectID lookup if available
    if (!post && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        post = await postsCollection.findOne({ _id: new ObjectId(req.params.id) });
        console.log('ObjectId lookup result:', post ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by title if still not found
    if (!post) {
      // Search by title as a last resort
      post = await postsCollection.findOne({ title: { $regex: new RegExp(req.params.id, 'i') } });
      console.log('Title search result:', post ? 'Found' : 'Not found');
    }

    if (!post) {
      // Log the full database structure if still not found
      console.log('Post still not found, checking database structure...');
      
      // Get collection structure
      const postsSample = await postsCollection.find().limit(1).toArray();
      console.log('Sample post structure:', JSON.stringify(postsSample, null, 2));
      
      console.error('Post not found with ID:', req.params.id);
      return res.status(404).send('Post not found');
    }

    // Convert MongoDB document to a JavaScript object
    const postObject = JSON.parse(JSON.stringify(post));
    
    // Get unique regions from posts
    const uniqueRegions = [...new Set(posts
      .map(p => p.region)
      .filter(region => region && region !== 'All')
    )].sort();

    res.render('edit-post', { 
      post: postObject,
      uniqueRegions
    });
  } catch (error) {
    console.error('Error finding post:', error);
    res.status(500).send('Server error');
  }
});

// Update both category detail routes with direct MongoDB access
app.get('/categories/:id', async (req, res) => {
  try {
    console.log('Accessing category with ID:', req.params.id);
    
    // DIRECT COLLECTION ACCESS
    const categoriesCollection = robolutionDb.collection('categories');
    
    // Try multiple query approaches
    let category = null;
    
    // 1. Try direct string ID lookup
    category = await categoriesCollection.findOne({ _id: req.params.id });
    console.log('Direct string ID lookup result:', category ? 'Found' : 'Not found');
    
    // 2. Try ObjectID lookup if available
    if (!category && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        category = await categoriesCollection.findOne({ _id: new ObjectId(req.params.id) });
        console.log('ObjectId lookup result:', category ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by title if still not found
    if (!category) {
      category = await categoriesCollection.findOne({ title: { $regex: new RegExp(req.params.id, 'i') } });
      console.log('Title search result:', category ? 'Found' : 'Not found');
    }
    
    if (category) {
      // Convert MongoDB document to a JavaScript object
      const categoryObject = JSON.parse(JSON.stringify(category));
      res.render('category-details', { event: categoryObject });
    } else {
      // Log the full database structure if still not found
      console.log('Category still not found, checking database structure...');
      
      // Get collection structure
      const categorySample = await categoriesCollection.find().limit(1).toArray();
      console.log('Sample category structure:', JSON.stringify(categorySample, null, 2));
      
      console.error('Event not found with ID:', req.params.id);
      res.status(404).send('Event not found');
    }
  } catch (error) {
    console.error('Error fetching category details:', error);
    res.status(500).send('An error occurred while fetching the category details');
  }
});

app.get('/user-categories/:id', async (req, res) => {
  try {
    console.log('Accessing user category with ID:', req.params.id);
    
    // DIRECT COLLECTION ACCESS
    const categoriesCollection = robolutionDb.collection('categories');
    
    // Try multiple query approaches
    let category = null;
    
    // 1. Try direct string ID lookup
    category = await categoriesCollection.findOne({ _id: req.params.id });
    console.log('Direct string ID lookup result:', category ? 'Found' : 'Not found');
    
    // 2. Try ObjectID lookup if available
    if (!category && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        category = await categoriesCollection.findOne({ _id: new ObjectId(req.params.id) });
        console.log('ObjectId lookup result:', category ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by title if still not found
    if (!category) {
      category = await categoriesCollection.findOne({ title: { $regex: new RegExp(req.params.id, 'i') } });
      console.log('Title search result:', category ? 'Found' : 'Not found');
    }
    
    if (category) {
      // Convert MongoDB document to a JavaScript object
      const categoryObject = JSON.parse(JSON.stringify(category));
      res.render('UserViews/user-category_details', { event: categoryObject });
    } else {
      // Log the full database structure if still not found
      console.log('Category still not found, checking database structure...');
      
      // Get collection structure
      const categorySample = await categoriesCollection.find().limit(1).toArray();
      console.log('Sample category structure:', JSON.stringify(categorySample, null, 2));
      
      console.error('Event not found with ID:', req.params.id);
      res.status(404).send('Event not found');
    }
  } catch (error) {
    console.error('Error fetching category details:', error);
    res.status(500).send('An error occurred while fetching the category details');
  }
});

// Update route to view individual registration details with direct MongoDB access
app.get('/registration/:id', async (req, res) => {
  try {
    console.log('Accessing registration with ID:', req.params.id);
    
    // DIRECT COLLECTION ACCESS
    const registrationsCollection = robolutionDb.collection('registrations');
    
    // Try multiple query approaches
    let registration = null;
    
    // 1. Try direct string ID lookup
    registration = await registrationsCollection.findOne({ _id: req.params.id });
    console.log('Direct string ID lookup result:', registration ? 'Found' : 'Not found');
    
    // 2. Try ObjectID lookup if available
    if (!registration && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        registration = await registrationsCollection.findOne({ _id: new ObjectId(req.params.id) });
        console.log('ObjectId lookup result:', registration ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by email or fullname if still not found
    if (!registration) {
      registration = await registrationsCollection.findOne({ 
        $or: [
          { email: { $regex: new RegExp(req.params.id, 'i') } },
          { fullname: { $regex: new RegExp(req.params.id, 'i') } }
        ] 
      });
      console.log('Email/Name search result:', registration ? 'Found' : 'Not found');
    }
    
    if (!registration) {
      // Log the full database structure if still not found
      console.log('Registration still not found, checking database structure...');
      
      // Get collection structure
      const registrationSample = await registrationsCollection.find().limit(1).toArray();
      console.log('Sample registration structure:', JSON.stringify(registrationSample, null, 2));
      
      console.error('Registration not found with ID:', req.params.id);
      return res.status(404).send('Registration not found');
    }
    
    // Convert MongoDB document to a JavaScript object
    const registrationObject = JSON.parse(JSON.stringify(registration));
    
    res.render('registration-detail', { 
      registration: registrationObject, 
      user: req.session.user 
    });
  } catch (error) {
    console.error('Error fetching registration details:', error);
    res.status(500).send('An error occurred while fetching registration details');
  }
});

// Update the route to view user profile with direct MongoDB collection access
app.get('/profile', requireLogin, async (req, res) => { // Added requireLogin
  // Check if user is logged in -- REMOVED MANUAL CHECK
  // if (!req.session || !req.session.user || !req.session.user.id) {
  //   console.log('No valid session for profile access:', { 
  //     hasSession: !!req.session,
  //     hasUser: req.session ? !!req.session.user : false,
  //     userId: req.session && req.session.user ? req.session.user.id : null
  //   });
    
  //   // Add redirect parameter so user can return to profile page after logging in
  //   return res.redirect('/login?redirect=/profile');
  // }
  
  try {
    console.log('Attempting to find user with ID:', req.session.user.id);
    
    // DIRECT COLLECTION ACCESS
    const usersCollection = robolutionDb.collection('users');
    
    // Try multiple query approaches
    let user = null;
    
    // 1. Try direct string ID lookup
    user = await usersCollection.findOne({ _id: req.session.user.id });
    console.log('Direct string ID lookup result:', user ? 'Found' : 'Not found');
    
    // 2. Try ObjectID lookup if available
    if (!user && req.session.user.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        user = await usersCollection.findOne({ _id: new ObjectId(req.session.user.id) });
        console.log('ObjectId lookup result:', user ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by username if still not found
    if (!user && req.session.user.username) {
      user = await usersCollection.findOne({ username: req.session.user.username });
      console.log('Username lookup result:', user ? 'Found' : 'Not found');
    }
    
    // 4. Try by email if still not found and available
    if (!user && req.session.user.email) {
      user = await usersCollection.findOne({ email: req.session.user.email });
      console.log('Email lookup result:', user ? 'Found' : 'Not found');
    }
    
    if (!user) {
      // User not found in database - likely due to database restore
      console.log('User not found in database but has session:', req.session.user);
      
      // Log the full database structure
      console.log('User still not found, checking database structure...');
      
      // Get collection structure
      const userSample = await usersCollection.find().limit(1).toArray();
      console.log('Sample user structure:', JSON.stringify(userSample, null, 2));
      
      // Render an error page instead of redirecting to login
      return res.render('UserViews/user-error', {
        error: 'Account Not Found',
        message: 'Your user account could not be found in the database. This may be due to a recent database restore operation. Please sign up for a new account.',
        actionText: 'Sign Up',
        actionLink: '/signup',
        showLogoutButton: true
      });
    }
    
    // Convert MongoDB document to a JavaScript object
    const userObject = JSON.parse(JSON.stringify(user));
    
    // Calculate age from birth date if available
    let age = null;
    if (userObject.birthDate && userObject.birthDate.month && userObject.birthDate.year) {
      const currentDate = new Date();
      const currentMonth = currentDate.getMonth() + 1; // JavaScript months are 0-indexed
      const currentYear = currentDate.getFullYear();
      
      age = currentYear - userObject.birthDate.year;
      
      // If birth month is after current month, subtract 1 from age
      if (userObject.birthDate.month > currentMonth) {
        age--;
      }
    }
    
    // Get user's registrations with direct collection access
    let registrations = [];
    try {
      console.log(`Looking for registrations with userId: ${userObject._id}`);
      
      // Direct collection access
      const registrationsCollection = robolutionDb.collection('registrations');
      
      if (registrationsCollection) {
        // Try multiple approaches to find registrations
        const userId = userObject._id;
        const userIdString = userObject._id.toString ? userObject._id.toString() : userObject._id;
        const userEmail = userObject.email;
        
        let regQuery = { $or: [] };
        
        // Add user ID conditions
        if (userId) regQuery.$or.push({ userId: userId });
        if (userIdString) regQuery.$or.push({ userId: userIdString });
        
        // Try to convert to ObjectId if it's a string in the right format
        if (typeof userIdString === 'string' && userIdString.match(/^[0-9a-fA-F]{24}$/)) {
          try {
            const ObjectId = require('mongodb').ObjectId;
            regQuery.$or.push({ userId: new ObjectId(userIdString) });
          } catch (err) {
            console.error('Error converting userId to ObjectId:', err.message);
          }
        }
        
        // Add email condition if available
        if (userEmail) regQuery.$or.push({ email: userEmail });
        
        // Only run query if we have at least one condition
        if (regQuery.$or.length > 0) {
          console.log('Registration query:', JSON.stringify(regQuery));
          registrations = await registrationsCollection.find(regQuery).sort({ registeredAt: -1 }).toArray();
          console.log(`Found ${registrations.length} registrations`);
          
          // Convert registrations to plain objects
          registrations = JSON.parse(JSON.stringify(registrations));
        } else {
          console.log('No valid conditions for registration query');
        }
      } else {
        console.log('Registrations collection not found');
      }
    } catch (regError) {
      console.error('Error fetching registrations:', regError);
    }
    
    // Render the profile page with all necessary data
    res.render('UserViews/profile', { 
      user: userObject,
      age,
      registrations,
      profilePicture: userObject.profilePicture || '/images/default-profile.jpg'
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).send('Error fetching user profile');
  }
});

// Update account/admin/edit route with direct DB access
app.get('/account/admin/edit/:id', requireAdmin, async (req, res) => {
  try {
    console.log('Accessing admin account with ID:', req.params.id);
    
    // Try to access the admin account from both databases
    let admin = null;
    
    // 1. Try adminDB first with direct string ID
    if (db) {
      admin = await db.collection('admins').findOne({ _id: req.params.id });
      console.log('adminDB direct string ID lookup result:', admin ? 'Found' : 'Not found');
    }
    
    // 2. Try adminDB with ObjectID
    if (!admin && db && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        admin = await db.collection('admins').findOne({ _id: new ObjectId(req.params.id) });
        console.log('adminDB ObjectId lookup result:', admin ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try adminDB by username
    if (!admin && db) {
      admin = await db.collection('admins').findOne({ username: req.params.id });
      console.log('adminDB username lookup result:', admin ? 'Found' : 'Not found');
    }
    
    // 4. Try robolution admins collection as fallback
    if (!admin && robolutionDb) {
      // Try string ID first
      admin = await robolutionDb.collection('admins').findOne({ _id: req.params.id });
      console.log('robolutionDb admins direct string ID lookup result:', admin ? 'Found' : 'Not found');
      
      // Try ObjectID if needed
      if (!admin && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
        try {
          const ObjectId = require('mongodb').ObjectId;
          admin = await robolutionDb.collection('admins').findOne({ _id: new ObjectId(req.params.id) });
          console.log('robolutionDb admins ObjectId lookup result:', admin ? 'Found' : 'Not found');
        } catch (err) {
          console.error('Error with ObjectId conversion for robolutionDb:', err.message);
        }
      }
      
      // Try username in robolution admins
      if (!admin) {
        admin = await robolutionDb.collection('admins').findOne({ username: req.params.id });
        console.log('robolutionDb admins username lookup result:', admin ? 'Found' : 'Not found');
      }
    }
    
    if (!admin) {
      // Log the full database structure if still not found
      console.log('Admin still not found, checking database structure...');
      
      // Get collection structure from both DBs
      if (db) {
        const adminSample = await db.collection('admins').find().limit(1).toArray();
        console.log('Sample adminDB admin structure:', JSON.stringify(adminSample, null, 2));
      }
      
      if (robolutionDb) {
        const robolutionAdminSample = await robolutionDb.collection('admins').find().limit(1).toArray();
        console.log('Sample robolutionDb admin structure:', JSON.stringify(robolutionAdminSample, null, 2));
      }
      
      console.error('Admin account not found with ID:', req.params.id);
      return res.status(404).send('Admin account not found');
    }
    
    // Convert MongoDB document to a JavaScript object
    const adminObject = JSON.parse(JSON.stringify(admin));
    
    // Get unique regions for the dropdown menu using direct collection access
    const postsCollection = robolutionDb.collection('posts');
    const posts = await postsCollection.find().toArray();
    const uniqueRegions = [...new Set(posts
      .map(p => p.region)
      .filter(region => region && region !== 'All')
    )].sort();
    
    res.render('edit-admin', {
      admin: adminObject,
      user: req.session.user,
      uniqueRegions,
      dashboard: isDashboard // Pass dashboard status
    });
  } catch (error) {
    console.error('Error fetching admin account:', error);
    res.status(500).send('An error occurred while fetching account information');
  }
});

// Update account/user/edit route with direct MongoDB access
app.get('/account/user/edit/:id', requireAdmin, async (req, res) => {
  try {
    console.log('Accessing user account for editing with ID:', req.params.id);
    
    // DIRECT COLLECTION ACCESS
    const usersCollection = robolutionDb.collection('users');
    
    // Try multiple query approaches
    let userAccount = null;
    
    // 1. Try direct string ID lookup
    userAccount = await usersCollection.findOne({ _id: req.params.id });
    console.log('Direct string ID lookup result:', userAccount ? 'Found' : 'Not found');
    
    // 2. Try ObjectID lookup if available
    if (!userAccount && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        userAccount = await usersCollection.findOne({ _id: new ObjectId(req.params.id) });
        console.log('ObjectId lookup result:', userAccount ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by username or email if still not found
    if (!userAccount) {
      userAccount = await usersCollection.findOne({ 
        $or: [
          { username: req.params.id },
          { email: req.params.id }
        ]
      });
      console.log('Username/Email search result:', userAccount ? 'Found' : 'Not found');
    }
    
    if (!userAccount) {
      // Log the full database structure if still not found
      console.log('User account still not found, checking database structure...');
      
      // Get collection structure
      const userSample = await usersCollection.find().limit(1).toArray();
      console.log('Sample user account structure:', JSON.stringify(userSample, null, 2));
      
      console.error('User account not found with ID:', req.params.id);
      return res.status(404).send('User account not found');
    }
    
    // Convert MongoDB document to a JavaScript object
    const userAccountObject = JSON.parse(JSON.stringify(userAccount));
    
    // Get unique regions using direct collection access
    const postsCollection = robolutionDb.collection('posts');
    const posts = await postsCollection.find().toArray();
    const uniqueRegions = [...new Set(posts
      .map(p => p.region)
      .filter(region => region && region !== 'All')
    )].sort();
    
    res.render('edit-user', {
      userAccount: userAccountObject,
      currentUser: req.session.user,
      uniqueRegions
    });
  } catch (error) {
    console.error('Error fetching user account:', error);
    res.status(500).send('An error occurred while fetching account information');
  }
});

// Update admin/user-profiles/:id route with direct MongoDB access
app.get('/admin/user-profiles/:id', requireAdmin, async (req, res) => {
  try {
    console.log('Accessing user profile with ID:', req.params.id);
    
    // DIRECT COLLECTION ACCESS
    const usersCollection = robolutionDb.collection('users');
    
    // Try multiple query approaches
    let userProfile = null;
    
    // 1. Try direct string ID lookup
    userProfile = await usersCollection.findOne({ _id: req.params.id });
    console.log('Direct string ID lookup result:', userProfile ? 'Found' : 'Not found');
    
    // 2. Try ObjectID lookup if available
    if (!userProfile && req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        userProfile = await usersCollection.findOne({ _id: new ObjectId(req.params.id) });
        console.log('ObjectId lookup result:', userProfile ? 'Found' : 'Not found');
      } catch (err) {
        console.error('Error with ObjectId conversion:', err.message);
      }
    }
    
    // 3. Try by username or email if still not found
    if (!userProfile) {
      userProfile = await usersCollection.findOne({ 
        $or: [
          { username: req.params.id },
          { email: req.params.id }
        ]
      });
      console.log('Username/Email search result:', userProfile ? 'Found' : 'Not found');
    }
    
    if (!userProfile) {
      // Log the full database structure if still not found
      console.log('User profile still not found, checking database structure...');
      
      // Get collection structure
      const userSample = await usersCollection.find().limit(1).toArray();
      console.log('Sample user profile structure:', JSON.stringify(userSample, null, 2));
      
      console.error('User not found with ID:', req.params.id);
      return res.status(404).send('User not found');
    }
    
    // Convert MongoDB document to a JavaScript object
    const userProfileObject = JSON.parse(JSON.stringify(userProfile));
    
    // Calculate age from birth date if available
    let age = null;
    if (userProfileObject.birthDate && userProfileObject.birthDate.month && userProfileObject.birthDate.year) {
      const currentDate = new Date();
      const currentMonth = currentDate.getMonth() + 1;
      const currentYear = currentDate.getFullYear();
      
      age = currentYear - userProfileObject.birthDate.year;
      
      if (userProfileObject.birthDate.month > currentMonth) {
        age--;
      }
    }
    
    res.render('admin-view-user-profile', {
      userProfile: userProfileObject,
      age,
      profilePicture: userProfileObject.profilePicture || '/images/default-profile.jpg',
      user: req.session.user
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).send('Error fetching user profile');
  }
});

// Route to make a user an admin
app.get('/account/user/make-admin/:id', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    console.log(`Attempting to make user with ID: ${userId} an admin.`);

    // Find the user in the User collection
    let userToPromote = null;
    const usersCollection = robolutionDb.collection('users');

    // 1. Try direct string ID lookup
    userToPromote = await usersCollection.findOne({ _id: userId });
    if (userToPromote) console.log('Found user by direct string ID in users collection.');

    // 2. Try ObjectID lookup if string ID failed
    if (!userToPromote && userId.match(/^[0-9a-fA-F]{24}$/)) {
      try {
        const ObjectId = require('mongodb').ObjectId;
        userToPromote = await usersCollection.findOne({ _id: new ObjectId(userId) });
        if (userToPromote) console.log('Found user by ObjectId in users collection.');
      } catch (err) {
        console.error('Error converting userId to ObjectId for users collection:', err.message);
      }
    }

    if (!userToPromote) {
      req.flash('error', 'User not found or ID is invalid.');
      return res.redirect('/manage-accounts');
    }

    console.log(`User found: ${userToPromote.username}. Preparing to promote.`);

    // Check if admin with the same username already exists in adminDB
    const adminDbAdminsCollection = db.collection('admins');
    const existingAdmin = await adminDbAdminsCollection.findOne({ username: userToPromote.username });

    if (existingAdmin) {
      console.log(`Admin with username ${userToPromote.username} already exists.`);
      req.flash('error', `An admin with username '${userToPromote.username}' already exists.`);
      return res.redirect('/manage-accounts');
    }

    // Prepare admin data
    const adminData = {
      username: userToPromote.username,
      password: userToPromote.password, // Copy hashed password
      role: 'admin', // Assign admin role
      twoFactorSecret: userToPromote.twoFactorSecret,
      twoFactorEnabled: userToPromote.twoFactorEnabled,
      backupCodes: userToPromote.backupCodes,
      needs2FASetup: userToPromote.needs2FASetup || false,
      createdAt: userToPromote.createdAt || new Date(),
      // Preserve original _id if possible, or let MongoDB generate a new one
      // _id: userToPromote._id 
    };
    
    // If the original user ID is an ObjectId, try to use it for the new admin record
    // Otherwise, let MongoDB generate a new _id for the admin record.
    if (userToPromote._id && (userToPromote._id.constructor.name === 'ObjectID' || userToPromote._id.constructor.name === 'ObjectId')) {
        adminData._id = userToPromote._id;
    } else if (typeof userToPromote._id === 'string' && userToPromote._id.match(/^[0-9a-fA-F]{24}$/)) {
        try {
            const ObjectId = require('mongodb').ObjectId;
            adminData._id = new ObjectId(userToPromote._id);
        } catch (e) {
            console.log('Could not convert user _id to ObjectId for admin record, will let MongoDB generate new _id');
        }
    }

    console.log('Admin data prepared:', adminData);

    // Insert into adminDB admins collection
    await adminDbAdminsCollection.insertOne(adminData);
    console.log(`User ${userToPromote.username} added to adminDB admins collection.`);

    // Also add/update in robolutionDb admins collection for redundancy and direct query consistency
    const robolutionDbAdminsCollection = robolutionDb.collection('admins');
    // Use upsert to add if not exists, or update if exists (e.g., if ID was preserved)
    await robolutionDbAdminsCollection.updateOne(
        { _id: adminData._id || new require('mongodb').ObjectId() }, // Match by ID if it was set
        { $set: adminData },
        { upsert: true }
    );
    console.log(`User ${userToPromote.username} upserted into robolutionDb admins collection.`);

    // Delete from the original User collection
    // Use the original _id from userToPromote for deletion
    let deleteResultUser;
    if (userToPromote._id.constructor.name === 'ObjectID' || userToPromote._id.constructor.name === 'ObjectId') {
        deleteResultUser = await usersCollection.deleteOne({ _id: userToPromote._id });
    } else if (typeof userToPromote._id === 'string' && userToPromote._id.match(/^[0-9a-fA-F]{24}$/)){
        deleteResultUser = await usersCollection.deleteOne({ _id: new require('mongodb').ObjectId(userToPromote._id) });
    } else {
        // Fallback to deleting by string id if it's not an ObjectId and doesn't look like one
        deleteResultUser = await usersCollection.deleteOne({ _id: userToPromote._id.toString() });
    }

    if (deleteResultUser.deletedCount === 1) {
      console.log(`User ${userToPromote.username} deleted from users collection.`);
      req.flash('success', `User '${userToPromote.username}' has been successfully promoted to admin.`);
    } else {
      console.log(`Failed to delete user ${userToPromote.username} from users collection. User might have already been deleted or ID mismatch.`);
      // Even if deletion fails, the admin record was created, so it's a partial success.
      // Log this as an inconsistency.
      req.flash('warning', `User '${userToPromote.username}' promoted to admin, but there was an issue removing the original user record. Please check manually.`);
    }

    res.redirect('/manage-accounts');

  } catch (error) {
    console.error('Error promoting user to admin:', error);
    req.flash('error', 'An error occurred while promoting the user to admin.');
    res.redirect('/manage-accounts');
  }
});

// Middleware to require login for regular users
const requireLogin = (req, res, next) => {
    if (!req.session.user || !req.session.user.id) {
        // Store the original URL to redirect back after login
        const redirectUrl = req.originalUrl;
        req.flash('error', 'You must be logged in to view this page.');
        return res.redirect(`/login?redirect=${encodeURIComponent(redirectUrl)}`);
    }
    next();
};

app.use('/images', express.static('public/images', {
  setHeaders: (res, path) => {
    if (path.endsWith('.webm')) {
      res.setHeader('Content-Type', 'video/webm');
    }
  }
}));

// Route for admin dashboard
app.get('/admin-dashboard', requireAdmin, async (req, res) => {
    try {
        const posts = await Post.find({}); // For uniqueRegions
        const uniqueRegions = [...new Set(posts.filter(post => post.region && post.region !== 'All').map(post => post.region))].sort();
        
        res.render('admin-dashboard', { 
            user: req.session.user,
            uniqueRegions: uniqueRegions,
            pageTitle: 'Admin Dashboard', // Optional: for consistency
            dashboard: true // Explicitly pass dashboard true for the main dashboard page itself
        });
    } catch (error) {
        console.error('Error loading admin dashboard:', error);
        req.flash('error', 'Error loading dashboard.');
        res.redirect('/login'); // Or an error page
    }
});

// ==== USER PROFILE ROUTES ==== 

// GET route to display user profile page
app.get('/profile', requireLogin, async (req, res) => {
    try {
        // The user object is already populated by requireLogin if successful,
        // but we need to fetch full details from DB
        const user = await User.findById(req.session.user.id);
        if (!user) {
            req.flash('error', 'User not found.');
            // If user somehow not found after login, redirect to login.
            return res.redirect('/login');
        }

        let age = null;
        if (user.birthDate && user.birthDate.month && user.birthDate.year) {
            const birthDate = new Date(user.birthDate.year, user.birthDate.month - 1);
            const today = new Date();
            age = today.getFullYear() - birthDate.getFullYear();
            const m = today.getMonth() - birthDate.getMonth();
            if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
                age--;
            }
        }

        const registrations = await Registration.find({ userId: user._id }).sort({ registeredAt: -1 });

        res.render('UserViews/profile', {
            user,
            age,
            registrations,
            profilePicture: user.profilePicture || '/images/default-profile.jpg'
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        req.flash('error', 'Error fetching profile.');
        res.redirect('/user-landing'); // Or a generic error page
    }
});

// POST route to update user profile
app.post('/profile/update', requireLogin, upload.single('profilePicture'), async (req, res) => {
    try {
        const { birthMonth, birthYear, school, address } = req.body;
        const user = await User.findById(req.session.user.id);

        if (!user) {
            // This should ideally not happen if requireLogin works
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (birthMonth && birthYear) {
            user.birthDate = { month: parseInt(birthMonth), year: parseInt(birthYear) };
        }
        // Allow clearing fields by providing empty strings
        user.school = school !== undefined ? school : user.school;
        user.address = address !== undefined ? address : user.address;

        if (req.file) {
            const filePath = req.file.path; // Path from multer
            const result = await uploadToCloudinary(filePath, 'robolution/profiles');
            user.profilePicture = result;
        }

        await user.save();
        res.json({ success: true, message: 'Profile updated successfully', profilePicture: user.profilePicture });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ success: false, message: 'Error updating profile' });
    }
});

// POST route to change user password from profile
app.post('/profile/change-password', requireLogin, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ success: false, message: 'All fields are required.' });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ success: false, message: 'New passwords do not match.' });
        }
         // Add password complexity check (example)
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.' });
        }

        const user = await User.findById(req.session.user.id);
        if (!user) {
            // Should not happen due to requireLogin
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect current password.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.json({ success: true, message: 'Password changed successfully.' });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ success: false, message: 'Error changing password.' });
    }
});

// Update routes for 2FA setup and verification
// ... existing code ...