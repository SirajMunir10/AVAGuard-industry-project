/**
 * AVAGuard Landing Page — GSAP Animations & Logic v3
 * Premium SaaS-grade interactive experience.
 */

// Force scroll to top on refresh
if ('scrollRestoration' in history) {
    history.scrollRestoration = 'manual';
}
window.scrollTo(0, 0);

document.addEventListener('DOMContentLoaded', () => {

    if (typeof gsap === 'undefined' || typeof ScrollTrigger === 'undefined') {
        console.error('GSAP or ScrollTrigger not loaded.');
        return;
    }
    gsap.registerPlugin(ScrollTrigger);

    const isMobile = window.matchMedia('(max-width: 1024px)').matches;

    /* ══════════════════════════════════════════
       1. CURSOR GLOW
    ══════════════════════════════════════════ */
    const glow = document.getElementById('cursorGlow');
    if (glow && !isMobile) {
        glow.classList.add('visible');
        document.addEventListener('mousemove', (e) => {
            glow.style.transform = `translate(${e.clientX - 250}px, ${e.clientY - 250}px)`;
        });
    }

    /* ══════════════════════════════════════════
       2. SCROLL PROGRESS BAR
    ══════════════════════════════════════════ */
    const progressBar = document.getElementById('scrollProgress');
    window.addEventListener('scroll', () => {
        const h = document.documentElement.scrollHeight - window.innerHeight;
        if (h > 0 && progressBar) {
            progressBar.style.width = `${(window.scrollY / h) * 100}%`;
        }
    }, { passive: true });

    /* ══════════════════════════════════════════
       3. NAV BEHAVIOR
    ══════════════════════════════════════════ */
    const nav = document.getElementById('mainNav');
    const hamburger = document.getElementById('navHamburger');
    const navLinks = document.getElementById('navLinks');

    // Solid on scroll
    ScrollTrigger.create({
        start: 'top -80',
        onUpdate: (self) => {
            nav.classList.toggle('scrolled', self.progress > 0);
        }
    });

    // Hamburger toggle
    if (hamburger && navLinks) {
        hamburger.addEventListener('click', () => {
            navLinks.classList.toggle('open');
        });
        // Close on link click (mobile)
        navLinks.querySelectorAll('a').forEach(a => {
            a.addEventListener('click', () => navLinks.classList.remove('open'));
        });
    }

    // Active section highlighting
    document.querySelectorAll('.nav-link').forEach(link => {
        const target = link.getAttribute('href');
        if (target && target.startsWith('#')) {
            const el = document.querySelector(target);
            if (el) {
                ScrollTrigger.create({
                    trigger: el,
                    start: 'top center',
                    end: 'bottom center',
                    onToggle: (self) => {
                        if (self.isActive) {
                            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                            link.classList.add('active');
                        }
                    }
                });
            }
        }
    });

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(a => {
        a.addEventListener('click', (e) => {
            const target = document.querySelector(a.getAttribute('href'));
            if (target) {
                e.preventDefault();
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });

    /* ══════════════════════════════════════════
       4. HERO ENTRANCE ANIMATIONS
    ══════════════════════════════════════════ */
    const heroTL = gsap.timeline({ delay: 0.1 });

    heroTL.fromTo('.gs-reveal, .trust-badges .badge',
        { y: 40, opacity: 0 },
        { y: 0, opacity: 1, duration: 0.8, stagger: 0.12, ease: 'power3.out' }
    )
    .fromTo('.hero-headline',
        { y: 30, opacity: 0 },
        { y: 0, opacity: 1, duration: 0.9, ease: 'power3.out' },
        '-=0.4'
    )
    .fromTo('.hero-sub',
        { y: 20, opacity: 0 },
        { y: 0, opacity: 1, duration: 0.7, ease: 'power3.out' },
        '-=0.3'
    )
    .fromTo('.hero-ctas',
        { y: 20, opacity: 0 },
        { y: 0, opacity: 1, duration: 0.6, ease: 'power3.out' },
        '-=0.2'
    )
    .fromTo('#dashMock',
        { x: 60, opacity: 0, rotationY: -25 },
        { x: 0, opacity: 1, rotationY: -12, duration: 1.2, ease: 'power3.out' },
        '-=0.8'
    );

    // Dashboard floating animation
    const dashMock = document.getElementById('dashMock');
    if (dashMock && !isMobile) {
        gsap.to(dashMock, {
            y: -12, rotationX: 7, rotationY: -8,
            duration: 3.5, repeat: -1, yoyo: true,
            ease: 'sine.inOut'
        });
    }

    // Animate ring and stat bars after hero loads
    setTimeout(() => {
        const ringFill = document.querySelector('.ring-fill');
        if (ringFill) ringFill.setAttribute('stroke-dasharray', '85, 100');

        document.querySelectorAll('.stat-fill.pass').forEach(el => el.style.width = '80%');
        document.querySelectorAll('.stat-fill.fail').forEach(el => el.style.width = '10%');
        document.querySelectorAll('.stat-fill.warn').forEach(el => el.style.width = '10%');
    }, 1200);

    /* ══════════════════════════════════════════
       5. NODE NETWORK CANVAS
    ══════════════════════════════════════════ */
    initNodeCanvas();

    /* ══════════════════════════════════════════
       6. PLATFORM SECTION ANIMATIONS
    ══════════════════════════════════════════ */
    gsap.fromTo('.platform-node', {
        y: 50, opacity: 0
    }, {
        y: 0, opacity: 1,
        duration: 0.8, stagger: 0.15,
        ease: 'power3.out',
        scrollTrigger: {
            trigger: '.platform-section',
            start: 'top 70%',
        }
    });

    gsap.fromTo('.connector-line', {
        opacity: 0, scaleY: 0
    }, {
        opacity: 1, scaleY: 1,
        duration: 0.6, stagger: 0.1,
        ease: 'power2.out',
        scrollTrigger: {
            trigger: '.platform-connectors',
            start: 'top 80%',
        }
    });

    /* ══════════════════════════════════════════
       7. SCROLL STORY (Pinned Narrative)
    ══════════════════════════════════════════ */
    const storySection = document.querySelector('.story-section');
    const storyPanels = gsap.utils.toArray('.story-panel');

    if (storySection && storyPanels.length >= 4) {
        const storyTL = gsap.timeline({
            scrollTrigger: {
                trigger: '.story-section',
                start: 'top top',
                end: `+=${isMobile ? 2500 : 4000}`,
                scrub: 1,
                pin: true,
            }
        });

        // Phase 1: CHAOS
        storyTL.to(storyPanels[0], { opacity: 1, duration: 1 })
               .to(storySection, { backgroundColor: '#1a0808', duration: 1 }, '-=0.5')
               .to(storyPanels[0], { opacity: 0, duration: 0.8 }, '+=0.8');

        // Phase 2: RISK (score drops)
        storyTL.to(storyPanels[1], { opacity: 1, duration: 1 })
               .to('#storyScore', {
                   innerText: 32, duration: 1.5, snap: { innerText: 1 },
                   ease: 'power2.in'
               }, '-=0.5')
               .to(storyPanels[1], { opacity: 0, duration: 0.8 }, '+=0.8');

        // Phase 3: COMPLEXITY (information overload)
        storyTL.to(storySection, { backgroundColor: '#1a1400', duration: 0.5 })
               .to(storyPanels[2], { opacity: 1, duration: 1 })
               .to(storyPanels[2], { opacity: 0, duration: 0.8 }, '+=1');

        // Phase 4: CONTROL (recovery)
        storyTL.to(storySection, { backgroundColor: '#0b0c10', duration: 1 })
               .to(storyPanels[3], { opacity: 1, duration: 1 })
               .to('#storyScoreUp', {
                   innerText: 87, duration: 1.5, snap: { innerText: 1 },
                   ease: 'power2.out'
               }, '-=0.5')
               .to(storyPanels[3], { opacity: 0, duration: 0.5 }, '+=1');
    }

    // Flying IDs for complexity phase
    const flyingContainer = document.getElementById('flyingIds');
    if (flyingContainer) {
        const ids = ['1.1', '1.3', '1.8', '2.1', '3.1', 'AC-2', 'IA-2', 'A.9.4.2', '1.11', '1.23', 'SC-20', 'IA-8', '1.5', 'AU-6'];
        ids.forEach(id => {
            const span = document.createElement('span');
            span.textContent = id;
            span.style.cssText = `
                position: absolute;
                left: ${Math.random() * 90}%;
                top: ${Math.random() * 80}%;
                opacity: ${0.3 + Math.random() * 0.5};
                animation: floatId ${2 + Math.random() * 3}s ease-in-out infinite alternate;
            `;
            flyingContainer.appendChild(span);
        });
        // Add keyframe
        const style = document.createElement('style');
        style.textContent = `@keyframes floatId { to { transform: translateY(-20px) translateX(${Math.random() > 0.5 ? '' : '-'}15px); opacity: 0.2; } }`;
        document.head.appendChild(style);
    }

    /* ══════════════════════════════════════════
       8. CAPABILITIES SHOWCASE (Sticky Scroll)
    ══════════════════════════════════════════ */
    const capBlocks = gsap.utils.toArray('.cap-block');
    const capVisuals = gsap.utils.toArray('.cap-vis');

    capBlocks.forEach((block, i) => {
        const targetId = block.getAttribute('data-vis');
        const targetVis = document.getElementById(targetId);

        ScrollTrigger.create({
            trigger: block,
            start: 'top center',
            end: 'bottom center',
            onEnter: () => activateVis(targetVis, block),
            onEnterBack: () => activateVis(targetVis, block),
        });
    });

    function activateVis(vis, block) {
        capVisuals.forEach(v => v.classList.remove('active'));
        capBlocks.forEach(b => b.classList.remove('active'));
        if (vis) vis.classList.add('active');
        if (block) block.classList.add('active');

        // Special animation for risk dial
        if (vis && vis.id === 'capVis2') {
            const needle = document.getElementById('dialNeedle');
            if (needle) {
                gsap.to(needle, { rotation: 70, duration: 1.5, ease: 'power2.out' });
            }
        }
    }

    /* ══════════════════════════════════════════
       9. HOW IT WORKS (Step Animation)
    ══════════════════════════════════════════ */
    const howSteps = gsap.utils.toArray('.how-step');

    howSteps.forEach((step, i) => {
        ScrollTrigger.create({
            trigger: step,
            start: 'top 75%',
            onEnter: () => {
                gsap.to(step, {
                    opacity: 1, y: 0,
                    duration: 0.6,
                    ease: 'power3.out',
                    delay: isMobile ? 0 : i * 0.15,
                    onComplete: () => step.classList.add('active')
                });
            },
            once: true
        });
    });

    /* ══════════════════════════════════════════
       10. ABOUT SECTION
    ══════════════════════════════════════════ */
    gsap.fromTo('.about-content > *', {
        y: 30, opacity: 0
    }, {
        y: 0, opacity: 1,
        duration: 0.7, stagger: 0.1,
        ease: 'power3.out',
        scrollTrigger: {
            trigger: '.about-section',
            start: 'top 65%',
        }
    });

    /* ══════════════════════════════════════════
       11. TEAM CARDS
    ══════════════════════════════════════════ */
    gsap.fromTo('.team-card', {
        y: 40, opacity: 0
    }, {
        y: 0, opacity: 1,
        duration: 0.7, stagger: 0.2,
        ease: 'power3.out',
        scrollTrigger: {
            trigger: '.team-section',
            start: 'top 65%',
        }
    });

    /* ══════════════════════════════════════════
       12. CONTACT FORM
    ══════════════════════════════════════════ */
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const btn = document.getElementById('contactBtn');
            const btnText = btn.querySelector('.btn-text');
            const btnLoader = btn.querySelector('.btn-loader');
            const successEl = document.getElementById('formSuccess');

            // Clear previous errors
            document.querySelectorAll('.form-error').forEach(el => el.textContent = '');
            document.querySelectorAll('.form-group').forEach(el => el.classList.remove('has-error'));

            const data = {
                name: document.getElementById('cfName').value.trim(),
                email: document.getElementById('cfEmail').value.trim(),
                subject: document.getElementById('cfSubject').value.trim(),
                message: document.getElementById('cfMessage').value.trim(),
            };

            // Client-side validation
            let hasError = false;
            if (!data.name) { showFieldError('errName', 'Name is required.'); hasError = true; }
            if (!data.email || !/^[^@]+@[^@]+\.[^@]+$/.test(data.email)) {
                showFieldError('errEmail', 'A valid email is required.'); hasError = true;
            }
            if (!data.subject) { showFieldError('errSubject', 'Subject is required.'); hasError = true; }
            if (!data.message) { showFieldError('errMessage', 'Message is required.'); hasError = true; }

            if (hasError) return;

            // Loading state
            btnText.style.display = 'none';
            btnLoader.style.display = 'inline';
            btn.disabled = true;

            try {
                const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
                const res = await fetch('/contact/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken,
                    },
                    body: JSON.stringify(data),
                });

                const result = await res.json();

                if (result.success) {
                    contactForm.reset();
                    successEl.style.display = 'block';
                    setTimeout(() => { successEl.style.display = 'none'; }, 5000);
                } else if (result.errors) {
                    Object.entries(result.errors).forEach(([field, msg]) => {
                        const errId = 'err' + field.charAt(0).toUpperCase() + field.slice(1);
                        showFieldError(errId, msg);
                    });
                }
            } catch (err) {
                console.error('Contact form error:', err);
            } finally {
                btnText.style.display = 'inline';
                btnLoader.style.display = 'none';
                btn.disabled = false;
            }
        });
    }

    function showFieldError(errId, msg) {
        const el = document.getElementById(errId);
        if (el) {
            el.textContent = msg;
            el.closest('.form-group')?.classList.add('has-error');
        }
    }

}); // End DOMContentLoaded


/* ══════════════════════════════════════════
   NODE NETWORK CANVAS
══════════════════════════════════════════ */
function initNodeCanvas() {
    const canvas = document.getElementById('nodesCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let w, h, nodes = [];
    const isMobile = window.matchMedia('(max-width: 768px)').matches;
    const nodeCount = isMobile ? 25 : 65;

    function resize() {
        const parent = canvas.parentElement;
        w = parent.clientWidth;
        h = parent.clientHeight;
        canvas.width = w;
        canvas.height = h;
    }

    window.addEventListener('resize', resize);
    resize();

    class Node {
        constructor() {
            this.x = Math.random() * w;
            this.y = Math.random() * h;
            this.vx = (Math.random() - 0.5) * 0.4;
            this.vy = (Math.random() - 0.5) * 0.4;
            this.r = Math.random() * 2 + 0.8;
        }
        update() {
            this.x += this.vx;
            this.y += this.vy;
            if (this.x < 0 || this.x > w) this.vx *= -1;
            if (this.y < 0 || this.y > h) this.vy *= -1;
        }
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(0, 212, 255, 0.5)';
            ctx.fill();
        }
    }

    for (let i = 0; i < nodeCount; i++) nodes.push(new Node());

    function animate() {
        ctx.clearRect(0, 0, w, h);

        for (const node of nodes) {
            node.update();
            node.draw();
        }

        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const dx = nodes[i].x - nodes[j].x;
                const dy = nodes[i].y - nodes[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 110) {
                    ctx.beginPath();
                    ctx.moveTo(nodes[i].x, nodes[i].y);
                    ctx.lineTo(nodes[j].x, nodes[j].y);
                    ctx.strokeStyle = `rgba(0, 212, 255, ${(1 - dist / 110) * 0.25})`;
                    ctx.lineWidth = 0.8;
                    ctx.stroke();
                }
            }
        }

        requestAnimationFrame(animate);
    }

    animate();
}
