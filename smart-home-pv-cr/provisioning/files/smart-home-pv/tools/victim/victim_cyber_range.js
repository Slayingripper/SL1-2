const puppeteer = require('puppeteer');
const dns = require('dns').promises;
const net = require('net');

const PV_URL = process.env['PV_URL'] || 'http://pv-controller';
const CHECK_EMAIL_INTERVAL = parseInt(process.env['CHECK_EMAIL_INTERVAL'] || '30') * 1000;
const VICTIM_EMAIL = process.env['VICTIM_EMAIL'] || 'admin@pv-controller.local';

/**
 * REALISTIC VICTIM SIMULATION
 * 
 * This victim:
 * 1. Periodically checks email
 * 2. Clicks on phishing links that look legitimate
 * 3. Enters credentials if page looks authentic
 * 4. Has some security awareness (checks for red flags)
 */

class RealisticVictim {
    constructor() {
        this.browser = null;
        this.page = null;
        this.credentials = {
            username: 'admin',
            password: 'PV-Sec-2024!Admin'  // Strong password
        };
        this.clickedLinks = new Set();
    }
    
    async init() {
        console.log('[Victim] Initializing browser...');
        
        this.browser = await puppeteer.launch({
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage'
            ],
            headless: true
        });
        
        this.page = await this.browser.newPage();
        
        // Set realistic user agent
        await this.page.setUserAgent(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        );
        
        // Log page console messages
        this.page.on('console', msg => console.log('[Page]', msg.text()));
        
        console.log('[Victim] Browser ready');
    }
    
    async checkEmail() {
        /**
         * Victim checks email inbox for new messages
         * Simulates periodic email checking behavior
         */
        try {
            console.log('[Victim] Checking email...');
            
            const response = await fetch(`${PV_URL}/api/internal/inbox`);
            const emails = await response.json();
            
            for (const email of emails) {
                // Skip already-clicked links
                if (this.clickedLinks.has(email.id)) {
                    continue;
                }
                
                // Evaluate if email is suspicious
                const suspicion = this.evaluateEmailSuspicion(email);
                
                console.log(`[Victim] Email: "${email.subject}" (suspicion: ${suspicion}%)`);
                
                // Victim more likely to click security-themed emails
                const clickProbability = this.calculateClickProbability(email, suspicion);
                
                if (Math.random() * 100 < clickProbability) {
                    console.log(`[Victim] 🎣 Clicking phishing link: ${email.link}`);
                    this.clickedLinks.add(email.id);
                    
                    // Show popup to the victim in browser before clicking
                    await this.showEmailPopup(email);
                    // Notify server
                    await fetch(`${PV_URL}/api/internal/phish_clicked`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({email_id: email.id})
                    });
                    
                    await this.visitPhishingLink(email);
                } else {
                    console.log(`[Victim] ⚠️  Email looks suspicious, ignoring`);
                }
            }
        } catch (error) {
            console.error('[Victim] Error checking email:', error.message);
        }
    }

    async showEmailPopup(email) {
        try {
            await this.page.evaluate((subject, body, link) => {
                // Create simple overlay
                const overlay = document.createElement('div');
                overlay.id = 'victim-email-popup';
                overlay.style.position = 'fixed';
                overlay.style.top = '20%';
                overlay.style.left = '50%';
                overlay.style.transform = 'translateX(-50%)';
                overlay.style.background = 'rgba(0,0,0,0.85)';
                overlay.style.color = 'white';
                overlay.style.border = '2px solid #ff5555';
                overlay.style.padding = '20px';
                overlay.style.zIndex = 9999;
                overlay.style.maxWidth = '600px';
                overlay.style.fontFamily = 'Arial, sans-serif';
                const title = document.createElement('div');
                title.style.fontSize = '18px';
                title.style.fontWeight = 'bold';
                title.style.marginBottom = '10px';
                title.innerText = `New Email: ${subject}`;
                overlay.appendChild(title);
                const text = document.createElement('div');
                text.style.maxHeight = '200px';
                text.style.overflowY = 'auto';
                text.style.marginBottom = '10px';
                text.innerText = body;
                overlay.appendChild(text);
                const btnReview = document.createElement('button');
                btnReview.innerText = 'Review';
                btnReview.style.marginRight = '10px';
                btnReview.onclick = () => { window.open(link, '_blank'); overlay.remove(); };
                const btnRelog = document.createElement('button');
                btnRelog.innerText = 'Relog';
                btnRelog.style.marginRight = '10px';
                btnRelog.onclick = () => { window.location.href = '/admin'; };
                const btnDismiss = document.createElement('button');
                btnDismiss.innerText = 'Dismiss';
                btnDismiss.onclick = () => overlay.remove();
                overlay.appendChild(btnReview);
                overlay.appendChild(btnRelog);
                overlay.appendChild(btnDismiss);
                document.body.appendChild(overlay);
            }, email.subject, email.body, email.link);
            console.log('[Victim] Displayed email popup to user');
        } catch (e) {
            console.error('[Victim] Failed to show popup', e.message);
        }
    }
    
    evaluateEmailSuspicion(email) {
        /**
         * Victim evaluates email for red flags
         * Returns suspicion percentage (0-100)
         */
        let suspicion = 0;
        
        // Check for common phishing indicators
        const subject = email.subject.toLowerCase();
        const body = email.body.toLowerCase();
        
        // RED FLAGS (increase suspicion)
        if (subject.includes('urgent') || subject.includes('immediate')) {
            suspicion += 10;
        }
        
        if (subject.includes('verify') || subject.includes('confirm')) {
            suspicion += 10;
        }
        
        if (subject.includes('suspended') || subject.includes('locked')) {
            suspicion += 15;
        }
        
        if (body.includes('click here') || body.includes('click now')) {
            suspicion += 10;
        }
        
        // Check link URL
        const link = email.link.toLowerCase();
        
        if (!link.includes('pv-controller') && !link.includes('172.20.0.65')) {
            suspicion += 20;  // External domain
        }
        
        if (link.includes('http://') && !link.includes('https://')) {
            suspicion += 5;  // No HTTPS
        }
        
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)) {
            // IP address in URL
            if (!link.includes('172.20.0')) {
                suspicion += 15;  // Suspicious IP
            }
        }
        
        // GREEN FLAGS (decrease suspicion)
        if (subject.includes('security alert') || subject.includes('password reset')) {
            suspicion -= 20;  // Victim more likely to trust security messages
        }
        
        return Math.max(0, Math.min(100, suspicion));
    }
    
    calculateClickProbability(email, suspicion) {
        /**
         * Calculate probability victim clicks the link
         * Based on email content and suspicion level
         */
        let probability = 50;  // Base 50% chance
        
        const subject = email.subject.toLowerCase();
        
        // Security-themed emails get higher click rate
        if (subject.includes('security') || subject.includes('alert')) {
            probability += 30;
        }
        
        if (subject.includes('password') || subject.includes('account')) {
            probability += 20;
        }
        
        // Reduce probability by suspicion
        probability -= suspicion;
        
        return Math.max(5, Math.min(95, probability));
    }
    
    async visitPhishingLink(email) {
        /**
         * Visit phishing link and evaluate page authenticity
         * Enter credentials only if page looks legitimate
         */
        try {
            console.log(`[Victim] Navigating to: ${email.link}`);
            
            await this.page.goto(email.link, {
                waitUntil: 'networkidle2',
                timeout: 15000
            });
            
            console.log('[Victim] Page loaded, evaluating authenticity...');
            
            // Evaluate page legitimacy
            const isLegitimate = await this.evaluatePageAuthenticity();
            
            if (isLegitimate) {
                console.log('[Victim] ✓ Page looks legitimate, entering credentials');
                await this.submitCredentials();
            } else {
                console.log('[Victim] ✗ Page looks suspicious, closing tab');
            }
            
        } catch (error) {
            console.error('[Victim] Error visiting phishing link:', error.message);
        }
    }
    
    async evaluatePageAuthenticity() {
        /**
         * Check if phishing page looks legitimate
         * Victims look for familiar branding, proper form structure
         */
        try {
            const checks = await this.page.evaluate(() => {
                const results = {
                    hasLoginForm: false,
                    hasUsernameField: false,
                    hasPasswordField: false,
                    hasLogo: false,
                    hasProperCSS: false,
                    hasSSLIndicator: false,
                    pageTitle: document.title
                };
                
                // Check for login form
                const forms = document.querySelectorAll('form');
                results.hasLoginForm = forms.length > 0;
                
                // Check for username field
                results.hasUsernameField = !!(
                    document.querySelector('input[name="username"]') ||
                    document.querySelector('input[type="text"]') ||
                    document.querySelector('input[placeholder*="user" i]')
                );
                
                // Check for password field
                results.hasPasswordField = !!(
                    document.querySelector('input[name="password"]') ||
                    document.querySelector('input[type="password"]')
                );
                
                // Check for logo/branding
                results.hasLogo = !!(
                    document.querySelector('.logo') ||
                    document.querySelector('img[alt*="logo" i]') ||
                    document.querySelector('[class*="brand" i]')
                );
                
                // Check if page has styling
                const styles = document.styleSheets;
                results.hasProperCSS = styles.length > 0;
                
                // Check for SSL/security indicator in page content
                results.hasSSLIndicator = document.body.innerHTML.toLowerCase().includes('secure');
                
                return results;
            });
            
            console.log('[Victim] Page evaluation:', JSON.stringify(checks, null, 2));
            
            // Decide if page is "legitimate enough"
            let score = 0;
            
            if (checks.hasLoginForm) score += 2;
            if (checks.hasUsernameField) score += 2;
            if (checks.hasPasswordField) score += 2;
            if (checks.hasLogo) score += 1;
            if (checks.hasProperCSS) score += 1;
            
            console.log(`[Victim] Legitimacy score: ${score}/8`);
            
            // Victim enters credentials if score >= 5
            return score >= 5;
            
        } catch (error) {
            console.error('[Victim] Error evaluating page:', error.message);
            return false;
        }
    }
    
    async submitCredentials() {
        /**
         * Fill in and submit login form
         */
        try {
            // Find username field
            const usernameSelector = 'input[name="username"], input[type="text"], input[placeholder*="user" i]';
            await this.page.waitForSelector(usernameSelector, {timeout: 3000});
            await this.page.type(usernameSelector, this.credentials.username);
            
            console.log('[Victim] Entered username');
            
            // Find password field
            const passwordSelector = 'input[name="password"], input[type="password"]';
            await this.page.waitForSelector(passwordSelector, {timeout: 3000});
            await this.page.type(passwordSelector, this.credentials.password);
            
            console.log('[Victim] Entered password');
            
            // Wait a bit (realistic user behavior)
            await this.page.waitForTimeout(1000);
            
            // Submit form
            const submitButton = await this.page.$('button[type="submit"], input[type="submit"], button');
            if (submitButton) {
                await submitButton.click();
                console.log('[Victim] 🚨 CREDENTIALS SUBMITTED TO PHISHING PAGE');
                
                // Wait for response
                await this.page.waitForTimeout(2000);
                
                // Notify server that credentials were submitted
                await fetch(`${PV_URL}/api/internal/phish_submitted`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: this.credentials.username,
                        password: this.credentials.password,
                        url: this.page.url()
                    })
                });
            }
            
        } catch (error) {
            console.error('[Victim] Error submitting credentials:', error.message);
        }
    }
    
    async routineWork() {
        /**
         * Simulate normal work activities (browsing admin dashboard)
         */
        try {
            console.log('[Victim] Performing routine work...');
            
            await this.page.goto(`${PV_URL}/admin`, {
                waitUntil: 'networkidle2',
                timeout: 15000
            });
            
            console.log('[Victim] Viewing admin dashboard');
            
            // Wait a bit (simulate reading)
            await this.page.waitForTimeout(5000);
            
        } catch (error) {
            console.error('[Victim] Error during routine work:', error.message);
        }
    }
    
    async run() {
        /**
         * Main victim behavior loop
         */
        await this.init();
        
        console.log('[Victim] Starting routine activities...');
        console.log(`[Victim] Checking email every ${CHECK_EMAIL_INTERVAL/1000}s`);
        
        // Main loop
        while (true) {
            try {
                // Check email
                await this.checkEmail();
                
                // Do some routine work
                if (Math.random() < 0.3) {  // 30% chance
                    await this.routineWork();
                }
                
                // Wait before next check
                await new Promise(resolve => setTimeout(resolve, CHECK_EMAIL_INTERVAL));
                
            } catch (error) {
                console.error('[Victim] Error in main loop:', error.message);
                await new Promise(resolve => setTimeout(resolve, 5000));
            }
        }
    }
}

// Wait for service availability
async function waitForService(host, port, timeoutMs=120000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        try {
            await dns.lookup(host);
            await new Promise((resolve, reject) => {
                const s = net.createConnection({host, port, timeout: 2000}, () => {
                    s.destroy();
                    resolve();
                });
                s.on('error', (e) => { s.destroy(); reject(e); });
                s.on('timeout', () => { s.destroy(); reject(new Error('timeout')); });
            });
            return true;
        } catch (e) {
            await new Promise(r => setTimeout(r, 2000));
        }
    }
    return false;
}

// Main entry point
(async () => {
    try {
        console.log('=' * 60);
        console.log('REALISTIC VICTIM SIMULATION');
        console.log('=' * 60);
        console.log(`Target: ${PV_URL}`);
        console.log(`Email: ${VICTIM_EMAIL}`);
        console.log('=' * 60);
        
        // Wait for PV controller to be available
        const url = new URL(PV_URL);
        const host = url.hostname;
        const port = Number(url.port) || 80;
        
        console.log(`[Victim] Waiting for ${host}:${port}...`);
        const ready = await waitForService(host, port);
        
        if (!ready) {
            console.error('[Victim] Service not available, exiting');
            process.exit(1);
        }
        
        console.log('[Victim] Service ready, starting simulation');
        
        // Run victim simulation
        const victim = new RealisticVictim();
        await victim.run();
        
    } catch (error) {
        console.error('[Victim] Fatal error:', error);
        process.exit(1);
    }
})();
