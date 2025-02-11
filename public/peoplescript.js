// Document Ready Handler
document.addEventListener('DOMContentLoaded', function() {
    initializeMobileMenu();
    initializeAnimations();
    initializeTabs();
    initializeTestimonialSlider();
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
                dropdown.classList.toggle('active');
            }
        });
    });

    // Close menu when clicking overlay
    menuOverlay?.addEventListener('click', () => {
        toggleMenu(false);
    });

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
        if (!navMenu.contains(e.target) && !mobileMenu.contains(e.target)) {
            toggleMenu(false);
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
        '.feature-block, .feature-card, .security-card, .integration-card, .testimonial-card'
    );

    animateElements.forEach(el => observer.observe(el));
}

// Tab Functionality
function initializeTabs() {
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

// Smooth Scroll for Navigation Links
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

// Form Validation (if needed)
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

// Add loading state to buttons
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
