// Initialize all functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeMobileMenu();
    initializeScrollReveal();
    initializeHorizontalNav();
    initializeBackToTop();
    initializeProgressBar();
    initializeCookieConsent();
    handleSmoothScroll();
    initializeAnimations();
    initializeHeaderScroll();
});

// Enhanced Mobile Menu with improved touch support
function initializeMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    const navMenu = document.getElementById('nav-menu');
    const menuOverlay = document.querySelector('.menu-overlay');
    const dropdowns = document.querySelectorAll('.dropdown');
    let isMenuOpen = false;

    // Toggle menu function with improved animation handling
    function toggleMenu(show) {
        isMenuOpen = show;
        mobileMenu?.classList.toggle('active', show);
        navMenu?.classList.toggle('active', show);
        menuOverlay?.classList.toggle('active', show);
        document.body.classList.toggle('no-scroll', show);

        // Reset all dropdowns when closing menu
        if (!show) {
            dropdowns.forEach(dropdown => {
                dropdown.classList.remove('active');
            });
        }
    }

    // Mobile menu button click handler
    mobileMenu?.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleMenu(!isMenuOpen);
    });

    // Enhanced dropdown handling for mobile
    dropdowns.forEach(dropdown => {
        const link = dropdown.querySelector('a');
        
        link?.addEventListener('click', (e) => {
            if (window.innerWidth <= 768) {
                e.preventDefault();
                e.stopPropagation();

                // Close other dropdowns
                dropdowns.forEach(d => {
                    if (d !== dropdown) {
                        d.classList.remove('active');
                    }
                });

                dropdown.classList.toggle('active');
            }
        });
    });

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
        if (isMenuOpen && !navMenu?.contains(e.target) && !mobileMenu?.contains(e.target)) {
            toggleMenu(false);
        }
    });

    // Close menu when clicking overlay
    menuOverlay?.addEventListener('click', () => {
        toggleMenu(false);
    });

    // Handle escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && isMenuOpen) {
            toggleMenu(false);
        }
    });
}

// Enhanced Side Navigation with Hamburger Menu
function initializeHorizontalNav() {
    const sideMenuToggle = document.querySelector('.side-menu-toggle');
    const sideNav = document.querySelector('.side-nav nav');
    const navLinks = document.querySelectorAll('.side-nav .nav-link');
    const sections = document.querySelectorAll('[data-section]');
    let isSideMenuOpen = false;
    let isScrolling = false;

    // Side menu toggle
    sideMenuToggle?.addEventListener('click', () => {
        isSideMenuOpen = !isSideMenuOpen;
        sideMenuToggle.classList.toggle('active', isSideMenuOpen);
        sideNav?.classList.toggle('active', isSideMenuOpen);
        
        // Handle overlay
        let overlay = document.querySelector('.side-nav-overlay');
        if (!overlay && isSideMenuOpen) {
            overlay = document.createElement('div');
            overlay.className = 'side-nav-overlay';
            document.body.appendChild(overlay);
        }
        
        if (overlay) {
            overlay.style.display = isSideMenuOpen ? 'block' : 'none';
            overlay.addEventListener('click', () => {
                closeSideMenu();
            });
        }

        document.body.classList.toggle('no-scroll', isSideMenuOpen);
    });

    function closeSideMenu() {
        isSideMenuOpen = false;
        sideMenuToggle?.classList.remove('active');
        sideNav?.classList.remove('active');
        document.querySelector('.side-nav-overlay')?.style.display = 'none';
        document.body.classList.remove('no-scroll');
    }

    // Desktop horizontal scroll handling
    if (sideNav && window.innerWidth > 768) {
        // Mouse wheel horizontal scroll
        sideNav.addEventListener('wheel', (e) => {
            if (e.deltaY !== 0) {
                e.preventDefault();
                sideNav.scrollLeft += e.deltaY;
            }
        });

        // Drag to scroll
        let isDown = false;
        let startX;
        let scrollLeft;

        sideNav.addEventListener('mousedown', (e) => {
            isDown = true;
            sideNav.style.cursor = 'grabbing';
            startX = e.pageX - sideNav.offsetLeft;
            scrollLeft = sideNav.scrollLeft;
        });

        sideNav.addEventListener('mouseleave', () => {
            isDown = false;
            sideNav.style.cursor = 'grab';
        });

        sideNav.addEventListener('mouseup', () => {
            isDown = false;
            sideNav.style.cursor = 'grab';
        });

        sideNav.addEventListener('mousemove', (e) => {
            if (!isDown) return;
            e.preventDefault();
            const x = e.pageX - sideNav.offsetLeft;
            const walk = (x - startX) * 2;
            sideNav.scrollLeft = scrollLeft - walk;
        });
    }

    // Update active section on scroll
    window.addEventListener('scroll', debounce(() => {
        if (!isScrolling) {
            let currentSection = '';
            sections.forEach(section => {
                const sectionTop = section.offsetTop - 100;
                const sectionHeight = section.offsetHeight;
                const scrollPosition = window.pageYOffset;

                if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
                    currentSection = section.getAttribute('data-section');
                }
            });

            navLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('data-section') === currentSection) {
                    link.classList.add('active');
                    if (window.innerWidth > 768) {
                        link.scrollIntoView({
                            behavior: 'smooth',
                            block: 'nearest',
                            inline: 'center'
                        });
                    }
                }
            });
        }
    }, 100));

    // Smooth scroll to section when clicking nav links
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href');
            const targetSection = document.querySelector(targetId);
            
            if (targetSection) {
                isScrolling = true;
                const offsetTop = targetSection.offsetTop - 80;
                
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });

                // Update active class
                navLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');

                // Close mobile side menu if open
                if (window.innerWidth <= 768) {
                    closeSideMenu();
                }

                // Reset isScrolling after animation
                setTimeout(() => {
                    isScrolling = false;
                }, 1000);
            }
        });
    });

    // Handle window resize
    window.addEventListener('resize', debounce(() => {
        if (window.innerWidth > 768 && isSideMenuOpen) {
            closeSideMenu();
        }
    }, 250));
}

// Scroll Reveal Animation
function initializeScrollReveal() {
    const observerOptions = {
        root: null,
        threshold: 0.1,
        rootMargin: '-50px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    document.querySelectorAll('.scroll-reveal').forEach(el => {
        observer.observe(el);
    });
}

// Back to Top Button
function initializeBackToTop() {
    const backToTop = document.getElementById('backToTop');
    if (!backToTop) return;

    window.addEventListener('scroll', debounce(() => {
        if (window.pageYOffset > 300) {
            backToTop.classList.add('visible');
        } else {
            backToTop.classList.remove('visible');
        }
    }, 100));

    backToTop.addEventListener('click', () => {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
}

// Progress Bar
function initializeProgressBar() {
    const progressBar = document.getElementById('progressBar');
    if (!progressBar) return;

    window.addEventListener('scroll', debounce(() => {
        const windowHeight = document.documentElement.scrollHeight - window.innerHeight;
        const scrolled = (window.pageYOffset / windowHeight) * 100;
        progressBar.style.width = `${scrolled}%`;
    }, 10));
}

// Header Scroll Effect
function initializeHeaderScroll() {
    const header = document.querySelector('header');
    if (!header) return;

    let lastScroll = 0;

    window.addEventListener('scroll', debounce(() => {
        const currentScroll = window.pageYOffset;
        
        if (currentScroll > 50) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }

        if (currentScroll > lastScroll && currentScroll > 300) {
            header.style.transform = 'translateY(-100%)';
        } else {
            header.style.transform = 'translateY(0)';
        }

        lastScroll = currentScroll;
    }, 50));
}

// Cookie Consent
function initializeCookieConsent() {
    const cookieConsent = document.getElementById('cookieConsent');
    const acceptButton = document.getElementById('acceptCookies');
    const settingsButton = document.getElementById('cookieSettings');

    if (!cookieConsent || !acceptButton) return;

    if (!localStorage.getItem('cookiesAccepted')) {
        setTimeout(() => {
            cookieConsent.classList.add('visible');
        }, 2000);
    }

    acceptButton.addEventListener('click', () => {
        localStorage.setItem('cookiesAccepted', 'true');
        cookieConsent.classList.remove('visible');
    });

    settingsButton?.addEventListener('click', () => {
        // Implement cookie settings functionality
        console.log('Cookie settings clicked');
    });
}

// Smooth Scroll
function handleSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            if (this.getAttribute('href') === '#') return;

            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                const headerOffset = 80;
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// Feature Card Animations
function initializeAnimations() {
    document.querySelectorAll('.feature-card').forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.classList.add('hover');
        });
        card.addEventListener('mouseleave', () => {
            card.classList.remove('hover');
        });
    });
}

// Utility Functions
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

// Handle loading state
window.addEventListener('load', () => {
    document.querySelector('.loading-overlay')?.style.display = 'none';
});

// Handle responsive layout
window.addEventListener('resize', debounce(() => {
    if (window.innerWidth > 768) {
        document.getElementById('mobile-menu')?.classList.remove('active');
        document.getElementById('nav-menu')?.classList.remove('active');
        document.querySelector('.menu-overlay')?.classList.remove('active');
        document.querySelector('.side-nav-overlay')?.classList.remove('active');
        document.body.classList.remove('no-scroll');
    }
}, 250));
