// Chart.js chart instance
let telemetryChart = null;
let telemetryData = [];
let chartCreating = false;
let shownNotifications = new Set(); // Track which notifications have been shown

// Notification system
async function checkNotifications() {
  try {
    const resp = await fetch('/api/notifications');
    if (!resp.ok) return;
    const data = await resp.json();
    
    // Show unread notifications as pop-ups
    (data.notifications || []).forEach(notif => {
      if (!notif.read && !shownNotifications.has(notif.id)) {
        showNotificationPopup(notif);
        shownNotifications.add(notif.id);
      }
    });
  } catch (e) {
    console.debug('Notification check failed', e);
  }
}

function showNotificationPopup(notif) {
  const container = document.getElementById('notification-container');
  if (!container) return;
  
  const popup = document.createElement('div');
  popup.className = 'notification-popup urgent';
  popup.innerHTML = `
    <div class="notification-header">
      <span class="notification-icon">⚠️</span>
      <span class="notification-title">${notif.title || 'System Alert'}</span>
      <button class="notification-close" onclick="closeNotification(${notif.id}, this)">×</button>
    </div>
    <div class="notification-body">
      <p>${notif.message}</p>
      ${notif.link ? `<a href="${notif.link}" class="notification-link" target="_blank" onclick="trackPhishingClick(${notif.id})">${notif.link_text || 'Click here'}</a>` : ''}
    </div>
  `;
  
  container.appendChild(popup);
  
  // Animate in
  setTimeout(() => popup.classList.add('show'), 10);
  
  // Auto-dismiss after 30 seconds
  setTimeout(() => {
    if (popup.parentElement) {
      closeNotification(notif.id, popup.querySelector('.notification-close'));
    }
  }, 30000);
}

window.closeNotification = async function(notificationId, button) {
  const popup = button.closest('.notification-popup');
  if (!popup) return;
  
  popup.classList.remove('show');
  setTimeout(() => popup.remove(), 300);
  
  // Mark as read on server
  try {
    await fetch(`/api/notifications/${notificationId}/read`, { method: 'POST' });
  } catch (e) {
    console.debug('Failed to mark notification as read', e);
  }
};

window.trackPhishingClick = function(notificationId) {
  // Track that user clicked the phishing link
  console.log('User clicked phishing link from notification', notificationId);
  closeNotification(notificationId, document.querySelector(`[onclick*="${notificationId}"]`));
};

async function loadDevices(){
  let resp = await fetch('/api/admin/devices');
  let data = await resp.json();
  let devicesDiv = document.getElementById('devices');
  devicesDiv.innerHTML = '';
  (data.devices || []).forEach(d=>{
    let el = document.createElement('div');
    el.className = 'device';
    // NOTE: This deliberately uses innerHTML to show stored XSS for training
    el.innerHTML = `<strong>${d.name}</strong><div>${d.description}</div>`;
    devicesDiv.appendChild(el);
  });
}

async function fetchMqttData(){
  let resp = await fetch('/admin/mqtt_data');
  if (!resp.ok) return [];
  let data = await resp.json();
  return data || [];
}

async function loadTelemetry(){
  const data = await fetchMqttData();
  // Convert to charted data points
  // store timestamps as numeric (seconds since epoch) to avoid date-adapter issues
  telemetryData = data.slice(-150).map(p => ({x: Number(p.ts) || Math.floor(new Date().getTime()/1000), y: Number(p.value) || Number(p.power) || 0}));
  updateChart();
  // Update status info
  let statusResp = await fetch('/status');
  if (statusResp.ok){
    const status = await statusResp.json();
    document.getElementById('pv-status').innerText = `Status: ${status.status}`;
    document.getElementById('pv-power').innerText = `Power: ${status.power || 0} W`;
    document.getElementById('pv-session').innerText = `MQTT Session: ${status.mqtt_session || ''}`;
  }
  // logs
    try {
      let mqttLogs = await (await fetch('/logs/mqtt_traffic.log')).text();
      let replayerLogs = ''
      try{ replayerLogs = await (await fetch('/logs/replayer.log')).text(); }catch(e){}
      document.getElementById('log-output').innerText = mqttLogs.slice(-2048) + '\n--- REPLAYER ---\n' + replayerLogs.slice(-1024);
    } catch(e) { /* ignore */ }
}

function updateChart(){
    if (!telemetryChart){
      chartCreating = true;
    const ctx = document.getElementById('telemetry-chart').getContext('2d');
    telemetryChart = new Chart(ctx, {
      type: 'line',
      data: {
        datasets: [{ label: 'Power (W)', data: telemetryData, borderColor: '#2b8cff', backgroundColor: 'rgba(43,140,255,0.06)', tension: 0.25 }]
      },
        options: {
        animation: false,
        responsive: true,
        scales: {
          // We'll use a numeric (linear) scale for time as unix timestamps (seconds) to avoid adapter incompat issues
          x: { type: 'linear', title: { display:true, text: 'Time (s since epoch)' }, ticks: { callback: (v) => new Date(v * 1000).toLocaleTimeString() } },
          y: { title: { display:true, text: 'Power (W)' }, beginAtZero: true }
        }
      }
    });
      chartCreating = false;
    } else {
    // update the underlying dataset and refresh chart
    telemetryChart.data.datasets[0].data = telemetryData;
    telemetryChart.update('none');
  }
}

window.addEventListener('DOMContentLoaded', ()=>{
  loadDevices();
  loadTelemetry();
  loadVictimStatus();
  checkNotifications(); // Check for notifications on load
  setInterval(checkNotifications, 3000); // Poll every 3 seconds
  
  document.getElementById('device-form').addEventListener('submit', async (ev)=>{
    ev.preventDefault();
    let name = document.getElementById('device-name').value;
    let desc = document.getElementById('device-desc').value;
    await fetch('/api/admin/devices', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, description:desc})});
    document.getElementById('device-name').value = '';
    document.getElementById('device-desc').value = '';
    loadDevices();
  });
  document.getElementById('refresh-btn').addEventListener('click', ()=>{ loadDevices(); loadTelemetry(); });
  document.getElementById('pcap-btn').addEventListener('click', ()=>{ window.open('/logs/traffic.pcap'); });
  document.getElementById('restart-btn').addEventListener('click', ()=>{ fetch('/api/hub/restart', {method:'POST'}).then(()=> loadTelemetry()); });
  document.getElementById('victim-refresh').addEventListener('click', async () => { await loadVictimStatus(); });
  document.getElementById('replayer-start').addEventListener('click', async ()=>{ await fetch('/replayer/start', {method:'POST'}); updateReplayerState(); });
  document.getElementById('replayer-stop').addEventListener('click', async ()=>{ await fetch('/replayer/stop', {method:'POST'}); updateReplayerState(); });

  async function updateReplayerState(){
    try{
      const resp = await fetch('/replayer/state');
      if (resp.ok){ const s = await resp.json(); document.getElementById('replayer-status').innerText = s.running ? 'Running' : 'Stopped'; }
    }catch(e){ }
  }

  async function loadVictimStatus(){
    try{
      const resp = await fetch('/victim/status');
      if (!resp.ok) return;
      const s = await resp.json();
      document.getElementById('victim-status').innerText = 'XSS detected: ' + s.xss_detected + "\n" + (s.recent || []).join('\n');
    }catch(e){ }
  }
  updateReplayerState();
  document.getElementById('halt-btn').addEventListener('click', async ()=>{
    const token = prompt('Enter admin token (or leave empty for simulation)');
    const headers = {'Content-Type':'application/json'};
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const res = await fetch('/api/hub/command', {method:'POST', headers, body: JSON.stringify({command:'HALT'})});
    if (!res.ok) alert('Command rejected: ' + res.status);
    loadTelemetry();
  });
  setInterval(loadTelemetry, 4000);
  // SSE for live MQTT telemetry updates
  if (window.EventSource) {
    try {
      // Try the normal path first, but fallback to '/sse/mqtt_stream' if unavailable
      let esurl = '/admin/mqtt_stream';
      const res = await fetch(esurl, {method:'GET', headers:{'Accept':'text/event-stream'}}).catch(()=>null);
      if (!res || res.status === 404) esurl = '/sse/mqtt_stream';
      const es = new EventSource(esurl);
      es.onmessage = (e) => {
        try {
            const p = JSON.parse(e.data);
          const point = { x: Number(p.ts) || Math.floor(new Date().getTime()/1000), y: Number(p.value) || Number(p.power) || 0 };
            telemetryData.push(point);
            // If chart is being created in parallel, skip updating the chart now
            if (chartCreating && !telemetryChart) return;
          telemetryData = telemetryData.slice(-150);
          updateChart();
          // update status area quickly when seeing pv/status
          if (p.topic === 'pv/status') {
            document.getElementById('pv-power').innerText = `Power: ${p.power || 0} W`;
          }
        } catch (err) { console.debug('SSE parse failed', err); }
      };
      es.onerror = (ev) => {
        console.warn('SSE connection closed or failed', ev);
        // If SSE fails repeatedly (404), fallback to polling every 4 seconds
        if (es.readyState === EventSource.CLOSED || (ev && ev.type === 'error')) {
          try { es.close(); } catch(_){}
          // Indicate fallback
          console.warn('SSE failing, falling back to polling');
        }
      };
    } catch (err) {
      console.warn('SSE not available', err);
    }
  }

  // Publish telemetry helper for testing (publish via admin endpoint)
  document.getElementById('publish-test').addEventListener('click', async ()=>{
    const val = Number(document.getElementById('publish-value').value) || 0;
    await fetch('/admin/publish_telemetry', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({power: val, ts: Math.floor(Date.now()/1000)}) });
  });
});
