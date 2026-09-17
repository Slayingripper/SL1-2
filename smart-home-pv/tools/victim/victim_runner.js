const puppeteer = require('puppeteer');
const dns = require('dns').promises;
const net = require('net');
const fetch = require('node-fetch');
const url = process.env['PV_URL'] || 'http://172.20.0.65/admin';
const pvHost = process.env['PV_HOST'] || 'pv-controller';
const pvBaseUrl = process.env['PV_BASE_URL'] || 'http://pv-controller';

async function waitForService(host, port, timeoutMs=60000, intervalMs=2000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      // Resolve hostname
      await dns.lookup(host);
      // Try connect to port
      await new Promise((resolve, reject) => {
        const s = net.createConnection({host, port, timeout: 2000}, () => { s.destroy(); resolve(); });
        s.on('error', (e) => { s.destroy(); reject(e); });
        s.on('timeout', () => { s.destroy(); reject(new Error('timeout')); });
      });
      return true;
    } catch (e) {
      // Not ready yet
      await new Promise(r => setTimeout(r, intervalMs));
    }
  }
  return false;
}

async function checkInboxAndClickPhishing(browser) {
  console.log('Victim: checking inbox for phishing emails...');
  
  // Poll inbox every 5 seconds
  const checkInterval = setInterval(async () => {
    try {
      const response = await fetch(`${pvBaseUrl}/api/internal/inbox`);
      const emails = await response.json();
      
      if (emails && emails.length > 0) {
        const latestEmail = emails[emails.length - 1];
        console.log(`Victim: received email - ${latestEmail.subject}`);
        
        if (latestEmail.link) {
          console.log(`Victim: clicking phishing link: ${latestEmail.link}`);
          
          // Notify server of click
          await fetch(`${pvBaseUrl}/api/internal/phish_clicked`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email_id: latestEmail.id})
          });
          
          // Try to open phishing page and submit credentials
          try {
            const phishPage = await browser.newPage();
            await phishPage.goto(latestEmail.link, {waitUntil: 'networkidle2', timeout: 10000});
            console.log('Victim: phishing page loaded');
            
            // Wait a bit (realistic user delay)
            await new Promise(r => setTimeout(r, 1000));
            
            // Fill in credentials (victim uses default admin credentials)
            await phishPage.evaluate(() => {
              const usernameField = document.querySelector('input[type="text"], input[name="username"], input[placeholder*="username" i]');
              const passwordField = document.querySelector('input[type="password"], input[name="password"]');
              const submitButton = document.querySelector('button[type="submit"], input[type="submit"], button');
              
              if (usernameField) usernameField.value = 'admin';
              if (passwordField) passwordField.value = 'admin123';
              if (submitButton) submitButton.click();
            });
            
            console.log('Victim: submitted credentials to phishing page');
            await phishPage.close();
          } catch (pageError) {
            console.log(`Victim: could not load phishing page - ${pageError.message}`);
          }
          
          // Always notify server directly (ensures credentials are captured)
          console.log('Victim: submitting credentials to server API');
          await fetch(`${pvBaseUrl}/api/internal/phish_submitted`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              username: 'admin', 
              password: 'admin123',
              email_id: latestEmail.id
            })
          });
          
          clearInterval(checkInterval);
        }
      }
    } catch (e) {
      console.log('Victim: inbox check error:', e.message);
    }
  }, 5000);
}

(async ()=>{
  console.log('Victim: launching headless browser to', url);
  // Ensure the PV host is resolvable and listening before launching browser
  try{
    const u = new URL(url);
    const host = u.hostname;
    const port = Number(u.port) || 80;
    console.log(`Victim: waiting for ${host}:${port} to become available`);
    const up = await waitForService(host, port, 120000, 2000);
    if (!up) {
      console.error(`Victim: ${host}:${port} not available after wait; aborting`);
      process.exit(1);
    }
  }catch(e){ console.warn('Victim: skip wait-for-service, URL parse failed or other', e); }

  const browser = await puppeteer.launch({args:['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage']});
  const page = await browser.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  
  // Start inbox monitoring for phishing
  checkInboxAndClickPhishing(browser);
  
  await page.goto(url, {waitUntil: 'networkidle2', timeout: 30000});
  console.log('Victim: page loaded');
  // send a keepalive log every 10 seconds
  setInterval(async () => {
    try{
      await page.evaluate(() => fetch('/victim/log', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({msg:'KEEPALIVE'})}));
    }catch(e){
    }
  }, 10000);
  // check for XSS: evaluate document.title change or a specific marker in DOM
    try{
      // Wait up to 15s for XSS effect to occur
      await page.waitForFunction(() => document.title.includes('XSS-TRIGGERED') || (document.querySelector('.device strong') && document.querySelector('.device strong').innerText.includes('<script>')), {timeout: 15000});
    console.log('Victim: XSS detected');
    // Notify server of detection
    try{ await page.evaluate(() => fetch('/victim/log', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({msg:'XSS DETECTED'})})); }catch(e){}
    process.exit(0);
  }catch(e){
    console.log('Victim: XSS not detected - retrying refresh and wait');
    try{ await page.reload({waitUntil: 'networkidle2'}); await page.waitForTimeout(5000); }catch(err){}
    try{
      const titleContains = await page.evaluate(() => document.title && document.title.includes('XSS-TRIGGERED'));
      if (titleContains){
        console.log('Victim: XSS detected after reload');
        process.exit(0);
      }
    }catch(err){}
    // Post a baseline log to server
    try{ await page.evaluate(() => fetch('/victim/log', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({msg:'PAGE_LOADED'})})); }catch(e){}
    console.log('Victim: finished without XSS');
    process.exit(2);
  }
})();
