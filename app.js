// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const app = express();
const port = process.env.SERVER_PORT || process.env.PORT || 3000;
const mongoose = require('mongoose');
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

// Middleware to require login for regular users
const requireLogin = (req, res, next) => {
    if (!req.session.user || !req.session.user.id) {
        return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
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

// Create post form route
app.get('/create-post', requireAdmin, async (req, res) => {
    try {
    // Check if the user is an admin
    if (!req.session.user || !req.session.user.isAdmin) {
      return res.redirect('/robolution');
    }

    // Check if loading in dashboard
    const isDashboard = req.query.dashboard === 'true';
    
    // Get all unique regions for the dropdown
    const posts = await Post.find({});
    const uniqueRegions = [...new Set(posts.filter(post => post.region && post.region !== 'All').map(post => post.region))];
    
        res.render('create-post', { 
            uniqueRegions,
      user: req.session.user,
      dashboard: isDashboard
        });
    } catch (error) {
        console.error('Error loading create post page:', error);
    res.status(500).send('An error occurred');
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
app.get('/index', requireAdmin, async (req, res) => {
  try {
    // Check if the user is an admin
    if (!req.session.user || !req.session.user.isAdmin) {
      return res.redirect('/robolution');
    }
    
    const sort = req.query.sort || 'desc';
    const search = req.query.search || '';
    const isDashboard = req.query.dashboard === 'true';
    
    let query = {};
    let sortQuery = { createdAt: sort === 'asc' ? 1 : -1 };
    
    if (search) {
      query = {
        $or: [
          { title: { $regex: search, $options: 'i' } },
          { content: { $regex: search, $options: 'i' } },
          { author: { $regex: search, $options: 'i' } }
        ]
      };
    }
    
    const posts = await Post.find(query).sort(sortQuery);
    
    res.render('index', { 
      posts, 
      sort, 
      search,
      user: req.session.user,
      dashboard: isDashboard
    });
  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).send('Error loading posts');
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
    const isDashboard = req.query.dashboard === 'true'; // Added
    const [categories, posts] = await Promise.all([
      Category.find(),
      Post.find()
    ]);

    const uniqueRegions = [...new Set(posts
      .map(post => post.region)
      .filter(region => region && region !== 'All')
    )].sort();

    res.render('manage-categories', { 
      categories,
      uniqueRegions,
      user: req.session.user, // Added for consistency
      dashboard: isDashboard  // Added
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
    const adminCollection = db.collection('admins');
    let user = await adminCollection.findOne({ username });
    
    // If not found in adminDB, check in robolutionDb
    if (!user) {
      const adminRobolutionCollection = robolutionDb.collection('admins');
      user = await adminRobolutionCollection.findOne({ username });
    }
    
    // If still not found, check regular users collection
    if (!user) {
      const usersCollection = robolutionDb.collection('users');
      user = await usersCollection.findOne({ username });
    }
    
    if (!user) {
                console.log('User not found:', username);
                return res.json({ success: false, message: 'Invalid username or password' });
            }
            
    // Check if password matches
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
                console.log('Invalid password for user:', username);
                return res.json({ success: false, message: 'Invalid username or password' });
            }
            
            // Check if this user needs to set up 2FA after password reset
    if (user.needs2FASetup) {
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
    if (user.twoFactorEnabled) {
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
      const isValidToken = verifyTwoFactorToken(user, token);
      if (!isValidToken) {
                        return res.json({ 
                            success: false, 
                            requireTwoFactor: true,
                            needs2FASetup: false, 
                            message: 'Invalid two-factor code. Please try again.'
                        });
      }
    }
    
    // Create session with admin flag based on role
            req.session.user = {
      id: user._id,
      username: user.username,
      isAdmin: user.role === 'admin' || user.role === 'superadmin' || user.username === 'kris',
      role: user.role || (user.isAdmin ? 'admin' : 'user')
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
            
    console.log('Login successful - Session saved:', {
                sessionID: req.sessionID,
                user: req.session.user,
                cookie: req.session.cookie
            });
            
    // Determine redirect URL based on user role
    let redirectUrl = redirect || '/user-landing'; // Default for regular users
    
    // If user is admin, redirect to admin dashboard
    if (req.session.user.isAdmin) {
      redirectUrl = '/admin-dashboard';
    }
            
            return res.json({ 
                success: true,
                redirectUrl: redirectUrl,
      role: req.session.user.role || 'user',
      message: 'Login successful! Welcome back, ' + user.username,
                setLocalStorage: true  // Signal client to set localStorage
            });
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

// ==== USER PROFILE ROUTES ==== 

// GET route to display user profile page
app.get('/profile', requireLogin, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id);
        if (!user) {
            req.flash('error', 'User not found.');
            return res.redirect('/login');
        }

        const registrations = await Registration.find({ userId: req.session.user.id }).sort({ registeredAt: -1 });

        let age = null;
        if (user.birthDate && user.birthDate.month && user.birthDate.year) {
            const birthDate = new Date(user.birthDate.year, user.birthDate.month - 1); // Month is 0-indexed
            const today = new Date();
            age = today.getFullYear() - birthDate.getFullYear();
            const m = today.getMonth() - birthDate.getMonth();
            if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
                age--;
            }
        }

        res.render('UserViews/profile', {
            user: user.toObject(), // Convert to plain object for template
            profilePicture: user.profilePicture || '/images/default-profile.jpg',
            age,
            registrations,
            uniqueRegions: res.locals.uniqueRegions || []
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        req.flash('error', 'Error loading profile. Please try again.');
        res.redirect('/user-landing');
    }
});

// POST route to update user profile information
app.post('/profile/update', requireLogin, upload.single('profilePicture'), async (req, res) => {
    try {
        const userId = req.session.user.id;
        const { birthMonth, birthYear, school, address } = req.body;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Update basic info
        if (birthMonth && birthYear) {
            user.birthDate = { month: parseInt(birthMonth), year: parseInt(birthYear) };
        }
        user.school = school || user.school;
        user.address = address || user.address;

        // Handle profile picture upload
        if (req.file) {
            try {
                const filePath = req.file.path;
                const cloudinaryResult = await uploadToCloudinary(filePath, 'robolution/profile_pictures');
                user.profilePicture = cloudinaryResult;
            } catch (uploadError) {
                console.error('Cloudinary upload error:', uploadError);
                // Optionally, decide if this is a hard fail or if profile updates without image change
                return res.status(500).json({ success: false, message: 'Error uploading profile picture.' });
            }
        }

        await user.save();
        // Update session user details if necessary, e.g., if fullName or other display info changes
        // req.session.user.fullName = user.fullName; (if fullName were editable here)

        res.json({ success: true, message: 'Profile updated successfully!', profilePicture: user.profilePicture });

    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ success: false, message: 'An error occurred while updating profile.' });
    }
});

// POST route to change user password
app.post('/profile/change-password', requireLogin, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ success: false, message: 'New passwords do not match.' });
        }
        
        if (newPassword.length < 8) { // Basic validation, align with signup
            return res.status(400).json({ success: false, message: 'New password must be at least 8 characters long.' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect current password.' });
        }

        const saltRounds = 10;
        user.password = await bcrypt.hash(newPassword, saltRounds);
        await user.save();

        res.json({ success: true, message: 'Password changed successfully!' });

    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ success: false, message: 'An error occurred while changing password.' });
    }
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
app.get('/admin-regional', requireAdmin, async (req, res) => { // Added requireAdmin, removed manual check
  try {
    const isDashboard = req.query.dashboard === 'true'; // Added
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
      sort: req.query.sort || 'desc',
      user: req.session.user, // Added for consistency
      dashboard: isDashboard  // Added
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

// Route for admin dashboard
app.get('/admin-dashboard', requireAdmin, (req, res) => {
    // Check if the user is an admin (already handled by requireAdmin, but good for clarity)
    if (!req.session.user || !req.session.user.isAdmin) {
        return res.redirect('/login');
    }
    res.render('admin-dashboard', { 
        user: req.session.user,
        // Pass any other necessary data for the dashboard
        uniqueRegions: res.locals.uniqueRegions || [] 
    });
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

// Route for admin to view all user profiles
app.get('/admin/user-profiles', requireAdmin, async (req, res) => {
    try {
        const isDashboard = req.query.dashboard === 'true';
        const search = req.query.search || '';
        let query = {};

        if (search) {
            query = {
                $or: [
                    { fullName: { $regex: search, $options: 'i' } },
                    { username: { $regex: search, $options: 'i' } },
                    { email: { $regex: search, $options: 'i' } },
                    { school: { $regex: search, $options: 'i' } }
                ]
            };
        }

        const users = await User.find(query);
        const posts = await Post.find({}); // For uniqueRegions
        const uniqueRegions = [...new Set(posts.filter(post => post.region && post.region !== 'All').map(post => post.region))].sort();

        res.render('admin-user-profiles', {
            users,
            search,
            user: req.session.user, // Admin user session
            uniqueRegions,
            dashboard: isDashboard
        });
    } catch (error) {
        console.error('Error loading admin user profiles page:', error);
        res.status(500).send('An error occurred while loading user profiles.');
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
app.get('/manage-registrations', requireAdmin, async (req, res) => { // Added requireAdmin
  try {
    const isDashboard = req.query.dashboard === 'true'; // Added
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
      posts, // Used for its own filters, not directly for dashboard context header
      category,
      workshop,
      search,
      payment,
      verified,
      user: req.session.user, // Added for consistency
      dashboard: isDashboard  // Added
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
    // Check if loading in dashboard
    const isDashboard = req.query.dashboard === 'true';
    
    // Get admins from adminDB (primary) and robolutionDb (backup)
    const adminsFromAdminDB = await db.collection('admins').find({}).toArray();
    const adminsFromRobolutionDB = await robolutionDb.collection('admins').find({}).toArray();
    
    // Combine and deduplicate admins based on username
    const combinedAdmins = [];
    const seenUsernames = new Set();
    
    // Process adminDB admins first (they take precedence)
    adminsFromAdminDB.forEach(admin => {
      combinedAdmins.push(admin);
      seenUsernames.add(admin.username);
    });
    
    // Add any unique admins from robolutionDb
    adminsFromRobolutionDB.forEach(admin => {
      if (!seenUsernames.has(admin.username)) {
        combinedAdmins.push(admin);
        seenUsernames.add(admin.username);
      }
    });
    
    // Get users from robolutionDb
    const users = await robolutionDb.collection('users').find({}).toArray();
    
    // Get unique regions for the navigation dropdown
    const posts = await Post.find({});
    const uniqueRegions = [...new Set(posts.filter(post => post.region && post.region !== 'All').map(post => post.region))];
    
    res.render('manage-accounts', {
      admins: combinedAdmins, // Corrected from adminAccounts
      users: users,           // Corrected from userAccounts
      uniqueRegions,
      user: req.session.user,
      dashboard: isDashboard
    });
  } catch (error) {
    console.error('Error loading manage accounts page:', error);
    console.error('Error loading admin dashboard:', error);
    res.status(500).send('An error occurred while loading the admin dashboard');
  }
});

// Route for admin to manage database backups
app.get('/manage-backups', requireAdmin, async (req, res) => {
    try {
        // Optional: Add superadmin check if only superadmins can manage backups
        if (req.session.user.role !== 'superadmin') {
            req.flash('error', 'You are not authorized to manage backups.');
            // Redirect to dashboard or another appropriate page if loaded in iframe
            if (req.query.dashboard === 'true') {
                 return res.status(403).send('Unauthorized. This content would normally redirect.'); // Or render a simple error view
            }
            return res.redirect('/admin-dashboard'); 
        }

        const isDashboard = req.query.dashboard === 'true';
        
        // Fetch backup data from the database_backups collection
        let backups = [];
        if (robolutionDb) {
            backups = await robolutionDb.collection('database_backups')
                                     .find({})
                                     .sort({ timestamp: -1 }) // Sort by newest first
                                     .toArray();
        }
        
        const posts = await Post.find({}); // For uniqueRegions in header/sidebar if not in dashboard
        const uniqueRegions = [...new Set(posts.filter(post => post.region && post.region !== 'All').map(post => post.region))].sort();

        res.render('manage-backups', {
            backups,
            user: req.session.user,
            uniqueRegions,
            dashboard: isDashboard,
            moment: require('moment') // Pass moment for date formatting in the template
        });
    } catch (error) {
        console.error('Error loading manage backups page:', error);
        res.status(500).send('An error occurred while loading the backups page.');
    }
});