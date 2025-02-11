// Document Ready Handler
document.addEventListener('DOMContentLoaded', function() {
    initializeMobileMenu();
    initializeAnimations();
    initializeFeatureHighlights();
    initializeTabPanels();
    initializeTestimonialSlider();
    initializePricingToggle();
});

// Mobile Menu Functionality
function initializeMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    const navMenu = document.getElementById('nav-menu');
    const menuOverlay = document.querySelector('.menu-overlay');
    const body = document.body;
    const dropdowns = document.querySelectorAll('.dropdown');

    // Toggle mobile menu
    mobileMenu?.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleMenu();
    });

    function toggleMenu(force = null) {
        const isActive = force !== null ? force : !mobileMenu.classList.contains('active');
        mobileMenu.classList.toggle('active', isActive);
        navMenu.classList.toggle('active', isActive);
        menuOverlay.classList.toggle('active', isActive);
        body.classList.toggle('menu-open', isActive);
    }

    // Handle dropdowns in mobile view
    dropdowns.forEach(dropdown => {
        const link = dropdown.querySelector('a');
        
        link?.addEventListener('click', (e) => {
            if (window.innerWidth <= 768) {
                e.preventDefault();
                e.stopPropagation();
                
                // Close other dropdowns
                dropdowns.forEach(other => {
                    if (other !== dropdown) {
                        other.classList.remove('active');
                    }
                });
                
                dropdown.classList.toggle('active');
            }
        });
    });

    // Close menu when clicking overlay
    menuOverlay?.addEventListener('click', () => {
        toggleMenu(false);
        dropdowns.forEach(dropdown => dropdown.classList.remove('active'));
    });

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
        if (!navMenu.contains(e.target) && !mobileMenu.contains(e.target)) {
            toggleMenu(false);
            dropdowns.forEach(dropdown => dropdown.classList.remove('active'));
        }
    });
}

// Scroll Animations
function initializeAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate');
                observer.unobserve(entry.target); // Only animate once
            }
        });
    }, observerOptions);

    // Observe elements that should animate on scroll
    const animateElements = document.querySelectorAll(
        '.benefit-card, .feature-card, .integration-item, .analytics-card, .security-card, .testimonial-card, .pricing-card, .resource-card'
    );

    animateElements.forEach(el => observer.observe(el));
}

// Feature Highlights Animation
function initializeFeatureHighlights() {
    const highlights = document.querySelectorAll('.highlight');
    
    highlights.forEach(highlight => {
        highlight.addEventListener('mouseenter', () => {
            highlight.style.transform = 'translateY(-5px)';
            highlight.style.background = '#f0f7ff';
        });

        highlight.addEventListener('mouseleave', () => {
            highlight.style.transform = 'translateY(0)';
            highlight.style.background = 'var(--card-bg)';
        });
    });
}

// Tab Panels for Features
function initializeTabPanels() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons and contents
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // Add active class to clicked button and corresponding content
            button.classList.add('active');
            const tabId = button.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });
}

// Testimonial Slider
function initializeTestimonialSlider() {
    const testimonials = document.querySelector('.testimonials-grid');
    if (!testimonials) return;

    let currentSlide = 0;
    const slides = testimonials.children;
    const totalSlides = slides.length;

    // Create navigation dots
    const dotsContainer = document.createElement('div');
    dotsContainer.className = 'slider-dots';
    
    for (let i = 0; i < totalSlides; i++) {
        const dot = document.createElement('button');
        dot.className = 'slider-dot';
        dot.addEventListener('click', () => goToSlide(i));
        dotsContainer.appendChild(dot);
    }

    testimonials.parentElement.appendChild(dotsContainer);

    function goToSlide(n) {
        currentSlide = n;
        updateSlider();
    }

    function updateSlider() {
        // Update slides
        for (let slide of slides) {
            slide.style.display = 'none';
        }
        slides[currentSlide].style.display = 'block';

        // Update dots
        const dots = dotsContainer.children;
        for (let dot of dots) {
            dot.classList.remove('active');
        }
        dots[currentSlide].classList.add('active');
    }

    // Auto-advance slides
    setInterval(() => {
        currentSlide = (currentSlide + 1) % totalSlides;
        updateSlider();
    }, 5000);

    // Initialize first slide
    updateSlider();
}

// Pricing Toggle
function initializePricingToggle() {
    const pricingCards = document.querySelectorAll('.pricing-card');
    
    pricingCards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            // Remove hover effect from featured card if not hovered
            pricingCards.forEach(otherCard => {
                if (otherCard !== card && otherCard.classList.contains('featured')) {
                    otherCard.style.transform = 'scale(1.05)';
                }
            });
        });

        card.addEventListener('mouseleave', () => {
            // Restore featured card scale
            pricingCards.forEach(otherCard => {
                if (otherCard.classList.contains('featured')) {
                    otherCard.style.transform = 'scale(1.05)';
                }
            });
        });
    });
}

// Form Validation
function validateForm(formElement) {
    const inputs = formElement.querySelectorAll('input[required], textarea[required]');
    let isValid = true;

    inputs.forEach(input => {
        if (!input.value.trim()) {
            isValid = false;
            input.classList.add('error');
        } else {
            input.classList.remove('error');
        }
    });

    return isValid;
}

// Handle form submissions
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        if (validateForm(this)) {
            // Add your form submission logic here
            console.log('Form submitted successfully');
        }
    });
});

// Smooth Scroll
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Window Resize Handler
let resizeTimer;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
        if (window.innerWidth > 768) {
            const mobileMenu = document.getElementById('mobile-menu');
            const navMenu = document.getElementById('nav-menu');
            const menuOverlay = document.querySelector('.menu-overlay');
            
            mobileMenu?.classList.remove('active');
            navMenu?.classList.remove('active');
            menuOverlay?.classList.remove('active');
            document.body.classList.remove('menu-open');
        }
    }, 250);
});

// Loading State for Buttons
document.querySelectorAll('.btn').forEach(button => {
    button.addEventListener('click', function() {
        if (this.classList.contains('loading')) return;
        
        const originalText = this.innerHTML;
        this.classList.add('loading');
        this.innerHTML = '<span class="spinner"></span> Loading...';

        // Simulate action completion (remove in production)
        setTimeout(() => {
            this.classList.remove('loading');
            this.innerHTML = originalText;
        }, 2000);
    });
});

// Debounce Helper Function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
