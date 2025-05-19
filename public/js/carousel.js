// Carousel logic with glitch effect for event title
document.addEventListener('DOMContentLoaded', function() {
    // Wait for the DOM to be fully loaded
    setTimeout(() => {
      initializeCarousel();
    }, 100);
    
    function initializeCarousel() {
      const cards = Array.from(document.querySelectorAll('.carousel-card'));
      const eventTitle = document.getElementById('carouselEventTitle');
      const indicatorsContainer = document.querySelector('.carousel-indicators');
      let current = 0;
      
      // If no cards exist, don't proceed
      if (cards.length === 0) return;
      
      // Reset all cards first
      cards.forEach(card => {
        card.classList.remove('active');
        card.style.opacity = '0';
        card.style.pointerEvents = 'none';
      });
      
      // Set the first card as active
      cards[0].classList.add('active');
      
      // Set initial title
      if (eventTitle && cards[0].dataset.title) {
        eventTitle.textContent = cards[0].dataset.title;
      }
      
      function setEventTitle(title) {
        if (!eventTitle) return;
        
        // Glitch effect: remove, force reflow, then add
        eventTitle.classList.remove('glitch');
        void eventTitle.offsetWidth; // force reflow
        eventTitle.textContent = title || 'Event Details';
        eventTitle.classList.add('glitch');
        setTimeout(() => eventTitle.classList.remove('glitch'), 500);
      }
      
      function updateCarousel() {
        const cardWidth = window.innerWidth < 768 ? 320 : 480; 
        const n = cards.length;
        const visibleRange = 2; 
        
        // First remove active class from all cards
        cards.forEach(card => card.classList.remove('active'));
        
        cards.forEach((card, idx) => {
          let rel = (idx - current + n) % n;
          if (rel > n / 2) rel -= n;
         
          let displayRel = rel;
          if (current === 0 && idx === n - 1) displayRel = -1; // last card to the left of first
          if (current === n - 1 && idx === 0) displayRel = 1;  // first card to the right of last
          
          // Scale and transform for different screen sizes
          const scale = rel === 0 ? (window.innerWidth < 768 ? 1.1 : 1.18) : (window.innerWidth < 768 ? 0.9 : 0.88);
          card.style.transform = `translateX(calc(-50% + ${rel * cardWidth}px)) scale(${scale})`;
          
          if (Math.abs(displayRel) <= visibleRange) {
            card.style.opacity = displayRel === 0 ? '1' : '0.6';
          } else {
            card.style.opacity = '0';
          }
          
          card.style.zIndex = displayRel === 0 ? 3 : 1;
          card.style.pointerEvents = displayRel === 0 ? 'auto' : 'none';
          
          // Mark the current card as active
          if (displayRel === 0) {
            card.classList.add('active');
          }
        });
        
        // Important: Only after updating all cards, set the title
        // This ensures we're getting the correct active card
        const activeCard = document.querySelector('.carousel-card.active');
        if (activeCard && activeCard.dataset.title) {
          setEventTitle(activeCard.dataset.title);
        }
        
        // Update indicators
        const indicators = document.querySelectorAll('.indicator-dot');
        if (indicators.length > 0) {
          indicators.forEach((dot, i) => {
            dot.classList.toggle('active', i === current);
          });
        }
      }
      
      function swipe(dir) {
        if (dir === 'left') {
          current = (current - 1 + cards.length) % cards.length;
        } else {
          current = (current + 1) % cards.length;
        }
        updateCarousel();
      }
      
      const leftButton = document.getElementById('carouselLeft');
      const rightButton = document.getElementById('carouselRight');
      
      if (leftButton) leftButton.addEventListener('click', () => swipe('left'));
      if (rightButton) rightButton.addEventListener('click', () => swipe('right'));
      
      // Handle indicator clicks
      document.addEventListener('indicator-click', function(e) {
        if (e.detail && typeof e.detail.index === 'number') {
          current = e.detail.index;
          updateCarousel();
        }
      });
      
      // Directly add listeners to indicator dots if they exist
      const dots = document.querySelectorAll('.indicator-dot');
      dots.forEach((dot, index) => {
        dot.addEventListener('click', function() {
          current = parseInt(dot.dataset.index || index);
          updateCarousel();
        });
      });
  
      // Swipe gesture support
      let startX = null;
      const carousel = document.querySelector('.carousel');
      
      if (carousel) {
        carousel.addEventListener('touchstart', e => {
          startX = e.touches[0].clientX;
        });
        
        carousel.addEventListener('touchend', e => {
          if (startX === null) return;
          let endX = e.changedTouches[0].clientX;
          if (endX - startX > 50) swipe('left');
          else if (startX - endX > 50) swipe('right');
          startX = null;
        });
      }
      
      // Initialize carousel display
      updateCarousel();
      
      // Random glitch effect for card descriptions
      function triggerRandomGlitch() {
        // Find all card descriptions
        const allDescriptions = document.querySelectorAll('.carousel-card-desc');
        
        if (allDescriptions.length > 0) {
          // Clear any ongoing glitch animations
          allDescriptions.forEach(desc => {
            desc.classList.remove('glitching');
          });
          
          // Randomly select one description
          const randomIndex = Math.floor(Math.random() * allDescriptions.length);
          const randomDesc = allDescriptions[randomIndex];
          
          // Force reflow and apply glitch class
          void randomDesc.offsetWidth;
          randomDesc.classList.add('glitching');
          
          // Remove class after animation completes
          setTimeout(() => {
            randomDesc.classList.remove('glitching');
          }, 2500);
        }
        
        // Schedule next glitch (random interval between 3-8 seconds)
        const nextGlitchDelay = 3000 + Math.random() * 5000;
        setTimeout(triggerRandomGlitch, nextGlitchDelay);
      }
      
      // Start random glitch effect if there are cards to animate
      triggerRandomGlitch();
      
      // Prevent hover from triggering glitch
      document.querySelectorAll('.carousel-card').forEach(card => {
        card.addEventListener('mouseenter', e => {
          const desc = card.querySelector('.carousel-card-desc');
          if (desc) {
            desc.classList.remove('glitching');
          }
        });
      });
      
      // Handle window resize
      window.addEventListener('resize', updateCarousel);
    }
  });