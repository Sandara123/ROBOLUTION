// Migration script to update comments in existing posts
// Run this script once after updating the Post schema

require('dotenv').config();
const mongoose = require('mongoose');
const Post = require('./models/Post');
const User = require('./models/User');

// Connect to MongoDB - use environment variable
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('MONGODB_URI environment variable is not set');
  process.exit(1);
}

console.log('Connecting to MongoDB...');
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected for migration'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

async function migrateComments() {
  try {
    console.log('Starting comment migration...');
    
    // Get all posts with comments
    const posts = await Post.find({ 'comments.0': { $exists: true } });
    console.log(`Found ${posts.length} posts with comments to migrate`);
    
    // Process each post
    for (const post of posts) {
      console.log(`Processing post: ${post._id} - ${post.title}`);
      let updated = false;
      
      // Get unique user IDs from comments
      const userIds = [];
      post.comments.forEach(comment => {
        try {
          // Handle different formats of user field
          if (comment.user) {
            if (typeof comment.user === 'string' || mongoose.Types.ObjectId.isValid(comment.user)) {
              userIds.push(comment.user.toString());
            } else if (comment.user._id) {
              userIds.push(comment.user._id.toString());
            }
          }
        } catch (err) {
          console.error(`Error processing comment user ID in post ${post._id}:`, err);
        }
      });
      
      // Fetch all users at once
      const users = await User.find({ _id: { $in: [...new Set(userIds)] } })
        .select('_id username profilePicture')
        .lean();
      
      console.log(`Found ${users.length} users for ${userIds.length} unique user IDs`);
      
      // Create a map for quick lookup
      const userMap = {};
      users.forEach(user => {
        userMap[user._id.toString()] = user;
      });
      
      // Update each comment
      for (let i = 0; i < post.comments.length; i++) {
        const comment = post.comments[i];
        
        // Skip if already in the new format
        if (comment.user && comment.user.username) {
          console.log(`Comment ${i} already in new format, skipping`);
          continue;
        }
        
        console.log(`Updating comment ${i} in post ${post._id}`);
        
        // Get the user ID
        let userId = null;
        try {
          if (comment.user) {
            if (typeof comment.user === 'string' || comment.user instanceof mongoose.Types.ObjectId) {
              userId = comment.user.toString();
            } else if (comment.user._id) {
              userId = comment.user._id.toString();
            }
          }
        } catch (err) {
          console.error(`Error extracting user ID from comment ${i}:`, err);
        }
        
        // Find the user in our map
        const user = userId && userMap[userId];
        
        if (user) {
          // Update to new format
          console.log(`Found user ${user.username} for comment ${i}`);
          post.comments[i].user = {
            _id: user._id,
            username: user.username,
            profilePicture: user.profilePicture || null
          };
        } else {
          // Set anonymous user if we can't find the user
          console.log(`No user found for comment ${i}, setting to Anonymous`);
          post.comments[i].user = {
            _id: comment.user || null,
            username: 'Anonymous User',
            profilePicture: null
          };
        }
        
        updated = true;
      }
      
      // Save the post if we made changes
      if (updated) {
        try {
          await post.save();
          console.log(`Updated comments for post: ${post._id}`);
        } catch (err) {
          console.error(`Error saving post ${post._id}:`, err);
        }
      } else {
        console.log(`No updates needed for post: ${post._id}`);
      }
    }
    
    console.log('Migration completed successfully');
  } catch (error) {
    console.error('Migration error:', error);
  } finally {
    mongoose.disconnect();
    console.log('MongoDB disconnected');
  }
}

// Run the migration
migrateComments(); 