/**
 * Mobile-specific JavaScript functionality
 */
document.addEventListener('DOMContentLoaded', function() {
  // Only run mobile-specific code on mobile devices
  if (window.innerWidth <= 768) {
    initMobileHeader();
    setupMobilePostsHeader();
    setupMobileScrolling();
    setupMobileCollapsibles();
    setupMobileCarousel();
    setupHeaderScrollEffect();
  }

  // Update on resize
  window.addEventListener('resize', function() {
    if (window.innerWidth <= 768) {
      setupMobilePostsHeader();
      setupMobileCollapsibles();
      setupMobileCarousel();
      setupHeaderScrollEffect();
    }
  });
});

/**
 * Initialize mobile header with dropdown menu
 */
function initMobileHeader() {
  // Create mobile menu toggle if it doesn't exist
  let mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
  const header = document.querySelector('header');
  const headerNav = document.querySelector('.header-nav');
  
  if (!mobileMenuToggle && header && headerNav) {
    // Create toggle button
    mobileMenuToggle = document.createElement('button');
    mobileMenuToggle.className = 'mobile-menu-toggle';
    mobileMenuToggle.innerHTML = '☰';
    header.querySelector('.header-content').appendChild(mobileMenuToggle);
    
    // Add toggle event
    mobileMenuToggle.addEventListener('click', function() {
      headerNav.classList.toggle('mobile-active');
      this.innerHTML = headerNav.classList.contains('mobile-active') ? '✕' : '☰';
    });
    
    // Setup dropdowns
    const dropdowns = headerNav.querySelectorAll('.dropdown');
    dropdowns.forEach(dropdown => {
      const dropdownBtn = dropdown.querySelector('.dropdown-btn');
      
      // Make dropdown button clickable separately from its href
      if (dropdownBtn) {
        dropdownBtn.addEventListener('click', function(e) {
          e.preventDefault();
          dropdown.classList.toggle('mobile-active');
        });
      }
    });
    
    // Close menu when clicking outside
    document.addEventListener('click', function(e) {
      if (!header.contains(e.target)) {
        headerNav.classList.remove('mobile-active');
        if (mobileMenuToggle) {
          mobileMenuToggle.innerHTML = '☰';
        }
        
        // Close any open dropdowns
        dropdowns.forEach(dropdown => {
          dropdown.classList.remove('mobile-active');
        });
      }
    });
  }
}

/**
 * Setup mobile carousel for better display on small screens
 */
function setupMobileCarousel() {
  const carousel = document.querySelector('.carousel');
  if (!carousel) return;
  
  // Get all carousel cards and arrows
  const cards = carousel.querySelectorAll('.carousel-card');
  const leftArrow = document.getElementById('carouselLeft');
  const rightArrow = document.getElementById('carouselRight');
  
  if (cards.length === 0) return;
  
  // Create mobile indicator dots
  let indicators = carousel.querySelector('.carousel-indicators');
  if (!indicators) {
    indicators = document.createElement('div');
    indicators.className = 'carousel-indicators';
    carousel.appendChild(indicators);
    
    // Create an indicator dot for each card
    cards.forEach((_, index) => {
      const dot = document.createElement('span');
      dot.className = 'indicator-dot';
      dot.dataset.index = index;
      indicators.appendChild(dot);
      
      // Add click event to dots
      dot.addEventListener('click', () => {
        activeIndex = index;
        updateActiveCard();
      });
    });
  }
  
  // Hide arrows on mobile but keep them functional in the DOM
  if (leftArrow) leftArrow.style.opacity = '0';
  if (rightArrow) rightArrow.style.opacity = '0';
  
  // Set the first card as active
  let activeIndex = 0;
  cards.forEach((card, index) => {
    if (index === activeIndex) {
      card.classList.add('active');
    } else {
      card.classList.remove('active');
    }
    
    // Fix card height and styling for mobile
    card.style.height = 'auto';
    card.style.minHeight = '420px';
    card.style.maxHeight = '550px';
    card.style.margin = '0 auto';
    card.style.width = '90%';
    card.style.position = index === activeIndex ? 'relative' : 'absolute';
    card.style.overflow = 'hidden';
    card.style.boxShadow = '0 4px 15px rgba(0, 0, 0, 0.1)';
    card.style.display = 'flex';
    card.style.flexDirection = 'column';
    
    // Position inactive cards properly
    if (index !== activeIndex) {
      card.style.left = '50%';
      card.style.transform = 'translateX(-50%)';
      card.style.top = '0';
    } else {
      card.style.left = 'auto';
      card.style.transform = 'none';
    }
    
    // Make sure images scale properly
    const img = card.querySelector('img');
    if (img) {
      img.style.width = '100%';
      img.style.height = '50%';
      img.style.objectFit = 'cover';
      img.style.maxHeight = '50%';
    }
    
    // Improve card content visibility
    const content = card.querySelector('.carousel-card-content');
    if (content) {
      content.style.padding = '15px';
      content.style.height = '50%';
      content.style.minHeight = '50%';
      content.style.display = 'flex';
      content.style.flexDirection = 'column';
      content.style.justifyContent = 'space-between';
      
      // Make description more visible
      const desc = content.querySelector('.carousel-card-desc');
      if (desc) {
        desc.style.marginBottom = '15px';
        desc.style.overflow = 'hidden';
        desc.style.display = '-webkit-box';
        desc.style.webkitLineClamp = '4';
        desc.style.webkitBoxOrient = 'vertical';
        desc.style.maxHeight = '5.6em';
      }
    }
  });
  
  // Handle arrow clicks
  if (leftArrow) {
    // Remove old event listeners
    const newLeftArrow = leftArrow.cloneNode(true);
    leftArrow.parentNode.replaceChild(newLeftArrow, leftArrow);
    
    newLeftArrow.addEventListener('click', function(e) {
      e.preventDefault();
      activeIndex = (activeIndex - 1 + cards.length) % cards.length;
      updateActiveCard();
    });
  }
  
  if (rightArrow) {
    // Remove old event listeners
    const newRightArrow = rightArrow.cloneNode(true);
    rightArrow.parentNode.replaceChild(newRightArrow, rightArrow);
    
    newRightArrow.addEventListener('click', function(e) {
      e.preventDefault();
      activeIndex = (activeIndex + 1) % cards.length;
      updateActiveCard();
    });
  }
  
  // Enhanced swipe support for mobile
  let touchStartX = 0;
  let touchEndX = 0;
  let initialOffset = 0;
  let currentTranslate = 0;
  let isDragging = false;
  
  // Add touch event listeners directly to carousel
  carousel.addEventListener('touchstart', handleTouchStart, { passive: true });
  carousel.addEventListener('touchmove', handleTouchMove, { passive: true });
  carousel.addEventListener('touchend', handleTouchEnd, { passive: true });
  
  function handleTouchStart(e) {
    touchStartX = e.touches[0].clientX;
    initialOffset = currentTranslate;
    isDragging = true;
    
    // Stop any ongoing animation
    cards.forEach(card => {
      card.style.transition = 'none';
    });
  }
  
  function handleTouchMove(e) {
    if (!isDragging) return;
    
    const currentX = e.touches[0].clientX;
    const diff = currentX - touchStartX;
    
    // Update current translate based on finger movement
    currentTranslate = initialOffset + diff;
    
    // Apply transform to create drag effect
    const activeCard = carousel.querySelector('.carousel-card.active');
    if (activeCard) {
      activeCard.style.transform = `translateX(${diff / 5}px)`;
    }
  }
  
  function handleTouchEnd(e) {
    if (!isDragging) return;
    isDragging = false;
    
    touchEndX = e.changedTouches[0].clientX;
    const activeCard = carousel.querySelector('.carousel-card.active');
    
    // Reset transition
    if (activeCard) {
      activeCard.style.transition = 'transform 0.3s ease';
      activeCard.style.transform = 'translateX(0)';
    }
    
    // Process the swipe
    const swipeDistance = touchEndX - touchStartX;
    
    // Determine if it's a significant swipe (more than 50px or 15% of screen width)
    const threshold = Math.max(50, window.innerWidth * 0.15);
    
    if (swipeDistance < -threshold) {
      // Swipe left - next slide
      activeIndex = (activeIndex + 1) % cards.length;
      updateActiveCard(true, 'left');
    } else if (swipeDistance > threshold) {
      // Swipe right - previous slide
      activeIndex = (activeIndex - 1 + cards.length) % cards.length;
      updateActiveCard(true, 'right');
    }
  }
  
  function updateActiveCard(animate = false, direction = null) {
    // Update all cards
    cards.forEach((card, index) => {
      if (index === activeIndex) {
        // Add animation when swiping
        if (animate) {
          card.style.animation = direction === 'left' 
            ? 'slideInRight 0.3s forwards' 
            : 'slideInLeft 0.3s forwards';
        }
        card.classList.add('active');
        // Set active card to relative position
        card.style.position = 'relative';
        card.style.left = 'auto';
        card.style.transform = 'none';
      } else {
        card.classList.remove('active');
        card.style.animation = '';
        // Set inactive cards to absolute position
        card.style.position = 'absolute';
        card.style.left = '50%';
        card.style.transform = 'translateX(-50%)';
        card.style.top = '0';
      }
    });
    
    // Update indicator dots
    const dots = carousel.querySelectorAll('.indicator-dot');
    dots.forEach((dot, index) => {
      if (index === activeIndex) {
        dot.classList.add('active');
      } else {
        dot.classList.remove('active');
      }
    });
    
    // Announce category change for screen readers
    const title = cards[activeIndex]?.getAttribute('data-title') || 'Category';
    const titleElement = document.getElementById('carouselEventTitle');
    if (titleElement) {
      titleElement.textContent = title;
    }
  }
  
  // Add keyboard support for accessibility
  window.addEventListener('keydown', function(e) {
    if (document.activeElement.closest('.carousel')) {
      if (e.key === 'ArrowLeft') {
        activeIndex = (activeIndex - 1 + cards.length) % cards.length;
        updateActiveCard();
      } else if (e.key === 'ArrowRight') {
        activeIndex = (activeIndex + 1) % cards.length;
        updateActiveCard();
      }
    }
  });
  
  // Initialize indicators
  updateActiveCard();
  
  // Add CSS for animations
  if (!document.getElementById('carouselAnimationStyle')) {
    const style = document.createElement('style');
    style.id = 'carouselAnimationStyle';
    style.textContent = `
      @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      @keyframes slideInLeft {
        from { transform: translateX(-100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      .carousel-indicators {
        display: flex;
        justify-content: center;
        gap: 8px;
        margin-top: 15px;
      }
      .indicator-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background-color: rgba(255, 255, 255, 0.5);
        cursor: pointer;
        transition: all 0.3s ease;
      }
      .indicator-dot.active {
        background-color: #fff;
        transform: scale(1.2);
      }
      .carousel-card {
        transition: opacity 0.3s ease;
      }
      .carousel-card:not(.active) {
        position: absolute;
        opacity: 0;
        pointer-events: none;
      }
    `;
    document.head.appendChild(style);
  }
}

/**
 * Setup mobile post headers for better formatting
 */
function setupMobilePostsHeader() {
  const postsHeader = document.querySelector('.posts-header');
  if (postsHeader) {
    // Ensure sort form gets full width on mobile
    const sortForm = postsHeader.querySelector('.sort-form');
    if (sortForm) {
      sortForm.style.width = '100%';
    }
  }
}

/**
 * Add smooth scrolling for better mobile experience
 */
function setupMobileScrolling() {
  // Add smooth scrolling to all internal links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      e.preventDefault();
      const targetId = this.getAttribute('href');
      if (targetId !== '#') {
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
          targetElement.scrollIntoView({
            behavior: 'smooth'
          });
        }
      } else {
        // For # links, scroll to top
        window.scrollTo({
          top: 0,
          behavior: 'smooth'
        });
      }
    });
  });
}

/**
 * Setup collapsible sections for mobile with better touch handling
 */
function setupMobileCollapsibles() {
  const collapsibles = document.querySelectorAll('.collapsible');
  
  collapsibles.forEach(button => {
    // Ensure we don't have double click handlers
    const newButton = button.cloneNode(true);
    button.parentNode.replaceChild(newButton, button);
    
    newButton.addEventListener('click', function() {
      this.classList.toggle('active');
      
      // Toggle the display of the next element (the content)
      const content = this.nextElementSibling;
      if (content.style.display === 'grid' || content.style.display === 'block') {
        content.style.display = 'none';
      } else {
        content.style.display = content.classList.contains('posts-grid') ? 'grid' : 'block';
      }
    });
  });
}

/**
 * Check if user is logged in using cookie or localStorage
 */
function checkLoginStatus() {
  const isLoggedIn = document.cookie.split(';').some((item) => item.trim().startsWith('robolution_session=')) || 
                      localStorage.getItem('isLoggedIn') === 'true';
  
  const loginButtons = document.querySelectorAll('.login-button');
  const signupButtons = document.querySelectorAll('.signup-button');
  const logoutButtons = document.querySelectorAll('.logout-button');
  
  if (isLoggedIn) {
    // User is logged in
    loginButtons.forEach(btn => { if (btn) btn.style.display = 'none'; });
    signupButtons.forEach(btn => { if (btn) btn.style.display = 'none'; });
    logoutButtons.forEach(btn => { if (btn) btn.style.display = 'inline-block'; });
  } else {
    // User is not logged in
    loginButtons.forEach(btn => { if (btn) btn.style.display = 'inline-block'; });
    signupButtons.forEach(btn => { if (btn) btn.style.display = 'inline-block'; });
    logoutButtons.forEach(btn => { if (btn) btn.style.display = 'none'; });
  }
}

// Run login check on page load
document.addEventListener('DOMContentLoaded', checkLoginStatus);

// Handle viewport height for mobile browsers (fixes issue with address bar)
function setMobileHeight() {
  const vh = window.innerHeight * 0.01;
  document.documentElement.style.setProperty('--vh', `${vh}px`);
}

// Set initial height and update on resize
setMobileHeight();
window.addEventListener('resize', setMobileHeight);

// Add touch events for better mobile interaction
function addTouchSupport() {
  // Improve touch functionality for carousels
  const carouselCards = document.querySelectorAll('.carousel-card');
  
  carouselCards.forEach(card => {
    let touchStartX = 0;
    let touchEndX = 0;
    
    card.addEventListener('touchstart', e => {
      touchStartX = e.changedTouches[0].screenX;
    }, {passive: true});
    
    card.addEventListener('touchend', e => {
      touchEndX = e.changedTouches[0].screenX;
      handleSwipe();
    }, {passive: true});
    
    function handleSwipe() {
      const swipeThreshold = 50;
      if (touchEndX < touchStartX - swipeThreshold) {
        // Swipe left
        document.getElementById('carouselRight')?.click();
      } else if (touchEndX > touchStartX + swipeThreshold) {
        // Swipe right
        document.getElementById('carouselLeft')?.click();
      }
    }
  });
  
  // Add active state for buttons on touch devices
  document.querySelectorAll('.nav-button, button, .back-to-top').forEach(element => {
    element.addEventListener('touchstart', () => {
      element.classList.add('touch-active');
    }, {passive: true});
    
    element.addEventListener('touchend', () => {
      element.classList.remove('touch-active');
    }, {passive: true});
  });
}

// Initialize touch support
if ('ontouchstart' in window || navigator.maxTouchPoints > 0) {
  document.addEventListener('DOMContentLoaded', addTouchSupport);
}

/**
 * Changes header color opacity based on scroll position
 * Header will be fully colored at the top and transparent when scrolled down
 */
function setupHeaderScrollEffect() {
  const header = document.querySelector('header');
  if (!header) return;
  
  // Initial state - fully colored header
  header.style.backgroundColor = 'rgba(0, 30, 60, 0.95)';
  
  // Function to update header based on scroll position
  function updateHeaderColor() {
    if (window.scrollY === 0) {
      // At the top - fully colored
      header.style.backgroundColor = 'rgba(0, 30, 60, 0.95)';
      header.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.5)';
    } else {
      // Scrolled down - semi-transparent
      header.style.backgroundColor = 'rgba(0, 30, 60, 0.7)';
      header.style.boxShadow = '0 2px 6px rgba(0, 0, 0, 0.3)';
    }
  }
  
  // Initial call
  updateHeaderColor();
  
  // Add scroll event listener
  window.addEventListener('scroll', updateHeaderColor, { passive: true });
} 