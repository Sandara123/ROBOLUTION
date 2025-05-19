/**
 * Robolution Website Main JavaScript
 * Handles collapsible sections, dropdowns, and other shared functionality
 */

console.log('Robolution website loaded!');

// Handle drag-and-drop file upload
const uploadContainer = document.querySelector('.upload-container');
const fileInput = document.querySelector('.image-upload');

if (uploadContainer) {
  uploadContainer.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadContainer.style.backgroundColor = '#b3e5fc';
  });

  uploadContainer.addEventListener('dragleave', () => {
    uploadContainer.style.backgroundColor = '#e9f7fa';
  });

  uploadContainer.addEventListener('drop', (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) {
      fileInput.files = e.dataTransfer.files;
    }
  });
}

// Initialize all collapsible sections and add event listeners
function initCollapsibleSections() {
  console.log('Initializing collapsible sections');
  const collapsibles = document.querySelectorAll('.collapsible');
  console.log('Found', collapsibles.length, 'collapsible sections');

  if (collapsibles.length === 0) return;

  // Add arrow elements to any collapsibles that don't have them
  collapsibles.forEach(function(button) {
    // Check if button already has an arrow
    if (!button.querySelector('.arrow')) {
      const arrow = document.createElement('span');
      arrow.className = 'arrow';
      arrow.textContent = '▼';
      button.appendChild(arrow);
    }
  });

  collapsibles.forEach(function(button, index) {
    // Make sure we don't add duplicate listeners by removing first
    button.removeEventListener('click', handleCollapsibleClick);
    button.addEventListener('click', handleCollapsibleClick);
    
    // Check if this section should be expanded by default
    const isFirstSection = index === 0;
    const parentIsRegionContainer = button.closest('.region-container') !== null;
    const parentIsYearSection = button.closest('.year-section') !== null;
    const isFirstInContainer = 
      (parentIsRegionContainer && button === button.closest('.region-container').querySelector('.collapsible')) ||
      (parentIsYearSection && button === button.closest('.year-section').querySelector('.collapsible'));
    
    // Auto-expand the first section by default
    if (isFirstSection || isFirstInContainer) {
      button.classList.add('active');
      // Make sure the arrow shows the correct state
      const arrow = button.querySelector('.arrow');
      if (arrow) {
        arrow.style.transform = 'translateY(-50%) rotate(180deg)';
      }
      
      const content = button.nextElementSibling;
      if (content) {
        const displayType = content.classList.contains('posts-grid') ? 'grid' : 'block';
        content.style.display = displayType;
        content.style.maxHeight = content.scrollHeight + 1000 + 'px';
        content.style.opacity = '1';
      }
    }
  });
}

// Handle click on collapsible button
function handleCollapsibleClick() {
  console.log('Collapsible clicked');
  // Toggle the active class which controls the arrow display
  this.classList.toggle('active');
  
  // Explicitly control the arrow rotation for maximum compatibility
  const arrow = this.querySelector('.arrow');
  if (arrow) {
    if (this.classList.contains('active')) {
      arrow.style.transform = 'translateY(-50%) rotate(180deg)';
    } else {
      arrow.style.transform = 'translateY(-50%) rotate(0deg)';
    }
  }
  
  // Toggle the display of the next element (the content)
  const content = this.nextElementSibling;
  if (!content) return;
  
  // Simple slide toggle animation
  if (content.style.maxHeight) {
    content.style.maxHeight = null;
    content.style.opacity = '0';
    // Keep display for a short time to allow animation
    setTimeout(() => {
      content.style.display = 'none';
    }, 300);
  } else {
    content.style.display = content.classList.contains('posts-grid') ? 'grid' : 'block';
    content.style.opacity = '0';
    
    // Trigger reflow to ensure animation works
    content.offsetHeight;
    
    // Set max height to allow animation
    content.style.maxHeight = content.scrollHeight + 1000 + 'px'; // Add extra height for safety
    content.style.opacity = '1';
  }
}

// Handle collapsible sections
document.addEventListener('DOMContentLoaded', function() {
  // Wait a moment for the page to fully load
  setTimeout(initCollapsibleSections, 100);
  
  // Check if we need to organize the regional page
  const isRegionalPage = window.location.pathname.includes('/regional');
  if (isRegionalPage) {
    const urlParams = new URLSearchParams(window.location.search);
    const regionParam = urlParams.get('region');
    
    if (regionParam === 'All') {
      // Organize by region instead of by year
      organizeRegionalPage();
    }
  }
});

// Function to handle regional page organization
function organizeRegionalPage() {
  console.log('Organizing regional page by regions');
  
  // Get all posts and organize them by region instead of by year
  const allPosts = document.querySelectorAll('.post-card');
  const postsByRegion = {};
  
  // Hide existing year sections
  document.querySelectorAll('.year-section').forEach(section => {
    section.style.display = 'none';
  });
  
  // Create region container if it doesn't exist
  let regionContainer = document.querySelector('.region-container');
  if (!regionContainer) {
    regionContainer = document.createElement('div');
    regionContainer.className = 'region-container';
    const mainElement = document.querySelector('main');
    if (mainElement) {
      // Find the position to insert - after posts-header
      const postsHeader = mainElement.querySelector('.posts-header');
      if (postsHeader) {
        postsHeader.after(regionContainer);
      } else {
        mainElement.appendChild(regionContainer);
      }
    }
  } else {
    regionContainer.innerHTML = '';
  }
  
  // Group posts by region
  allPosts.forEach(post => {
    const regionBadge = post.querySelector('.region-badge');
    if (regionBadge) {
      const region = regionBadge.textContent.trim();
      if (!postsByRegion[region]) {
        postsByRegion[region] = [];
      }
      postsByRegion[region].push(post.cloneNode(true));
    }
  });
  
  // If no region badge found, try to extract from data attribute or other sources
  if (Object.keys(postsByRegion).length === 0) {
    allPosts.forEach(post => {
      // Default to "Unknown Region" if we can't determine
      let region = "Unknown Region";
      
      // Try to get region from a data attribute (add this to your template if needed)
      if (post.dataset.region) {
        region = post.dataset.region;
      }
      
      if (!postsByRegion[region]) {
        postsByRegion[region] = [];
      }
      postsByRegion[region].push(post.cloneNode(true));
    });
  }
  
  // Create sections for each region
  Object.keys(postsByRegion).sort().forEach(region => {
    const regionSection = document.createElement('div');
    regionSection.className = 'region-section';
    
    const button = document.createElement('button');
    button.className = 'collapsible';
    button.innerHTML = region + ' <span class="arrow">▼</span>';
    regionSection.appendChild(button);
    
    const postsGrid = document.createElement('div');
    postsGrid.className = 'posts-grid';
    postsGrid.style.display = 'none';
    
    postsByRegion[region].forEach(post => {
      postsGrid.appendChild(post);
    });
    
    regionSection.appendChild(postsGrid);
    regionContainer.appendChild(regionSection);
  });
  
  // Re-initialize collapsible sections
  setTimeout(initCollapsibleSections, 100);
}

// Overlap check for header, footer, nav buttons
function checkOverlap() {
  const footer = document.querySelector('.fixed-footer');
  const header = document.querySelector('header');
  const navButtons = document.querySelectorAll('.nav-button:not(.registration-button)');
  const videoSection = document.querySelector('.video-section');

  if (!footer || !header || !videoSection) return;

  const footerRect = footer.getBoundingClientRect();
  const headerRect = header.getBoundingClientRect();
  const videoRect = videoSection.getBoundingClientRect();

  const footerOverlapping = (
    footerRect.top < videoRect.bottom &&
    footerRect.bottom > videoRect.top
  );

  const headerOverlapping = (
    headerRect.bottom > videoRect.top &&
    headerRect.top < videoRect.bottom
  );

  // Footer overlap
  if (footerOverlapping) {
    footer.classList.add('overlap');
  } else {
    footer.classList.remove('overlap');
  }

  // Header overlap
  if (headerOverlapping) {
    header.classList.add('overlap');
    navButtons.forEach(btn => btn.classList.add('overlap'));
  } else {
    header.classList.remove('overlap');
    navButtons.forEach(btn => btn.classList.remove('overlap'));
  }
}

// Events - Run on all pages
document.addEventListener('DOMContentLoaded', function() {
  // Check overlap initially and set up listeners
  checkOverlap();
  window.addEventListener('resize', checkOverlap);
  window.addEventListener('scroll', checkOverlap);
  
  // Handle back-to-top button
  const backToTopButton = document.getElementById('backToTop');
  
  if (backToTopButton) {
    window.addEventListener('scroll', function() {
      if (window.pageYOffset > 300) {
        backToTopButton.classList.add('show');
      } else {
        backToTopButton.classList.remove('show');
      }
    });
    
    backToTopButton.addEventListener('click', function(e) {
      e.preventDefault();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }
  
  // Handle image upload previews
  const setupImageUpload = function(container, input, preview) {
    if (!container || !input || !preview) return;
    
    container.addEventListener('click', function() {
      input.click();
    });

    container.addEventListener('dragover', function(e) {
      e.preventDefault();
      this.classList.add('dragover');
    });

    container.addEventListener('dragleave', function() {
      this.classList.remove('dragover');
    });

    container.addEventListener('drop', function(e) {
      e.preventDefault();
      this.classList.remove('dragover');
      if (e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        showPreview(e.dataTransfer.files[0], preview);
      }
    });

    input.addEventListener('change', function() {
      if (this.files && this.files[0]) {
        showPreview(this.files[0], preview);
      }
    });
  };

  function showPreview(file, previewElement) {
    const reader = new FileReader();
    reader.onload = function(e) {
      previewElement.innerHTML = `<div class="image-preview-container"><img src="${e.target.result}" style="max-width:100%;max-height:120px;border-radius:8px;"><button type="button" class="delete-image-btn" onclick="removePreview()">✕</button></div>`;
    };
    reader.readAsDataURL(file);
  }
  
  // Setup image uploads on relevant pages
  const uploadContainer = document.getElementById('uploadContainer');
  const imageUpload = document.getElementById('imageUpload');
  const uploadPreview = document.getElementById('uploadPreview');
  
  if (uploadContainer && imageUpload && uploadPreview) {
    setupImageUpload(uploadContainer, imageUpload, uploadPreview);
  }
});

// Video context menu prevent
const video = document.querySelector('.video-section video');
if (video) {
  video.addEventListener('contextmenu', (event) => {
    event.preventDefault();
  });
}

function handleFooterResize() {
  const footer = document.querySelector('.fixed-footer');
  const socialIcons = document.querySelector('.social-icons');
  const video = document.querySelector('.video-section');
  const body = document.body;

  if (!footer || !socialIcons || !video) return;

  const footerRect = footer.getBoundingClientRect();
  const videoRect = video.getBoundingClientRect();

  const isOverVideo = (
    footerRect.top < videoRect.bottom &&
    footerRect.bottom > videoRect.top
  );

  const isAtBottom = window.innerHeight + window.scrollY >= body.offsetHeight - 2;

  if (isOverVideo || isAtBottom) {
    footer.classList.remove('footer-compact');
    socialIcons.style.display = 'flex';
  } else {
    footer.classList.add('footer-compact');
    socialIcons.style.display = 'none';
  }
}

window.addEventListener('scroll', handleFooterResize);
window.addEventListener('resize', handleFooterResize);
window.addEventListener('load', handleFooterResize);

// Delete buttons
const deleteButtons = document.querySelectorAll('.delete-btn');

