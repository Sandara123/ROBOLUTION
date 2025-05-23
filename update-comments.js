// Migration script to update comments in existing posts
// Run this script once after updating the Post schema

require('dotenv').config();
const mongoose = require('mongoose');
const Post = require('./models/Post');
const User = require('./models/User');

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
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
      const userIds = [...new Set(
        post.comments
          .filter(comment => comment.user && mongoose.Types.ObjectId.isValid(comment.user))
          .map(comment => comment.user.toString())
      )];
      
      // Fetch all users at once
      const users = await User.find({ _id: { $in: userIds } })
        .select('_id username profilePicture')
        .lean();
      
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
          continue;
        }
        
        // Get the user ID (could be ObjectId or string)
        let userId = comment.user;
        if (userId && typeof userId === 'object' && userId._id) {
          userId = userId._id.toString();
        } else if (userId) {
          userId = userId.toString();
        }
        
        // Find the user in our map
        const user = userId && userMap[userId];
        
        if (user) {
          // Update to new format
          post.comments[i].user = {
            _id: user._id,
            username: user.username,
            profilePicture: user.profilePicture || null
          };
        } else {
          // Set anonymous user if we can't find the user
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
        await post.save();
        console.log(`Updated comments for post: ${post._id}`);
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