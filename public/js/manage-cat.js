document.addEventListener('DOMContentLoaded', function() {
  // Handle new category image upload
  const uploadContainer = document.getElementById('uploadContainer');
  const imageUpload = document.getElementById('imageUpload');
  const uploadPreview = document.getElementById('uploadPreview');

  if (uploadContainer && imageUpload && uploadPreview) {
    setupImageUpload(uploadContainer, imageUpload, uploadPreview);
  }

  // Handle existing categories image uploads
  document.querySelectorAll('[id^="uploadContainer-"]').forEach(container => {
    const id = container.id.split('-')[1];
    const upload = document.getElementById(`imageUpload-${id}`);
    const preview = document.getElementById(`uploadPreview-${id}`);
    
    if (container && upload && preview) {
      setupImageUpload(container, upload, preview);
    }
  });

  function setupImageUpload(container, input, preview) {
    container.addEventListener('click', () => input.click());

    container.addEventListener('dragover', (e) => {
      e.preventDefault();
      container.classList.add('dragover');
    });

    container.addEventListener('dragleave', () => {
      container.classList.remove('dragover');
    });

    container.addEventListener('drop', (e) => {
      e.preventDefault();
      container.classList.remove('dragover');
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
  }

  function showPreview(file, previewElement) {
    const reader = new FileReader();
    reader.onload = function(e) {
      previewElement.innerHTML = `<img src="${e.target.result}" style="max-width:100%;max-height:120px;border-radius:8px;">`;
    };
    reader.readAsDataURL(file);
  }

  // Handle section toggles for both new and existing categories
  function setupSectionToggles(formElement) {
    const sections = [
      { box: 'showMechanics', area: 'mechanics' },
      { box: 'showGeneralConduct', area: 'generalConduct' },
      { box: 'showGeneralRules', area: 'generalRules' },
      { box: 'showParticipantsRequirement', area: 'participantsRequirement' },
      { box: 'showTeamRequirement', area: 'teamRequirement' }
    ];

    sections.forEach(({box, area}) => {
      const checkbox = formElement.querySelector(`[id^="${box}"]`);
      const textarea = formElement.querySelector(`[id^="${area}"]`);
      
      if (checkbox && textarea) {
        textarea.disabled = !checkbox.checked;
        checkbox.addEventListener('change', function() {
          textarea.disabled = !this.checked;
        });
      }
    });
  }

  // Setup toggles for new category form
  const addCategoryForm = document.getElementById('addCategoryForm');
  if (addCategoryForm) {
    setupSectionToggles(addCategoryForm);
  }

  // Setup toggles for existing category forms
  document.querySelectorAll('.category-edit-form').forEach(form => {
    setupSectionToggles(form);
  });

  // Handle image deletion
  window.deleteImage = async function(categoryId, imageUrl) {
    if (!confirm('Are you sure you want to remove this image?')) {
      return;
    }

    try {
      const response = await fetch(`/manage-categories/${categoryId}/delete-image`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ imageUrl: imageUrl })
      });

      const result = await response.json();

      if (response.ok && result.success) {
        // Clear the image preview and reset the file input
        const previewElement = document.getElementById(`uploadPreview-${categoryId}`);
        if (previewElement) {
          previewElement.innerHTML = 'Drag & Drop or Click to Add Photo';
        }

        // Find the closest form to the preview element
        const form = previewElement.closest('form');
        if (form) {
          // Find and clear the hidden input within this specific form
          const hiddenInput = form.querySelector('input[name="currentImageUrl"]');
          if (hiddenInput) {
            hiddenInput.value = '';
          }
        }

        // Clear the file input if it exists
        const fileInput = document.getElementById(`imageUpload-${categoryId}`);
        if (fileInput) {
          fileInput.value = '';
        }
      } else {
        const errorMessage = result.error || 'Failed to delete image. Please try again.';
        alert(errorMessage);
      }
    } catch (error) {
      console.error('Error deleting image:', error);
      alert('Failed to delete image. Please try again.');
    }
  };
});
