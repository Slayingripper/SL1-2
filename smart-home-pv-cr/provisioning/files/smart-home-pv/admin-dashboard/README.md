# PV SCADA HMI - Admin Dashboard

Professional React-based admin dashboard for the Smart Home PV Controller cyber range challenge.

## Features

- **Industrial SCADA Styling**: Dark theme with cybersecurity-inspired UI
- **Real-time MQTT Integration**: Live telemetry and status updates
- **Professional Login**: Requires stolen credentials from phishing attack
- **System Overview**: Metrics cards, system information, alerts
- **Power Analytics**: Chart.js visualizations of production data
- **Modbus Control**: Reference interface for Modbus TCP operations
- **Diagnostics Panel**: System logs, network status, **FLAG display**
- **Responsive Design**: Works on desktop and tablets

## Tech Stack

- **React 18** with TypeScript
- **Vite** for fast builds
- **Chart.js** for data visualization
- **MQTT.js** for real-time data
- **Axios** for API calls
- **CSS3** with animations and gradients

## Installation

```bash
cd admin-dashboard
npm install
```

## Development

```bash
# Start dev server (with hot reload)
npm run dev

# Access at http://localhost:3000
```

## Building for Production

```bash
# Build optimized static files
npm run build

# Output will be in dist/ directory
```

## Integration with Flask Backend

The Flask server serves the built React app from the `/admin` route:

```python
@app.route('/admin')
@app.route('/admin/<path:path>')
def serve_admin(path=''):
    if path and os.path.exists(os.path.join('admin-dashboard/dist', path)):
        return send_from_directory('admin-dashboard/dist', path)
    return send_from_directory('admin-dashboard/dist', 'index.html')
```

## Authentication Flow

1. User accesses `/admin` route
2. React app loads Login component
3. Login sends credentials to `/api/admin/login`
4. Backend validates: `admin:PV-Sec-2024!Admin`
5. Returns JWT token on success
6. Dashboard loads with token in Authorization header
7. Diagnostics panel fetches flag from `/api/admin/flag`

## API Endpoints Used

```
POST /api/admin/login
  Body: {"username": "admin", "password": "PV-Sec-2024!Admin"}
  Response: {"token": "eyJ..."}

GET /api/admin/flag
  Headers: Authorization: Bearer <token>
  Response: {"flag": "BSY{PV_ADMIN_ACCESS_...}"}

GET /api/admin/logs
  Headers: Authorization: Bearer <token>
  Response: {"logs": [...]}
```

## MQTT Configuration

Dashboard connects to MQTT broker via WebSocket:

```javascript
const client = mqtt.connect('ws://172.20.0.66:9001');
client.subscribe('pv/status');
client.subscribe('pv/telemetry');
```

**Note**: Requires MQTT WebSocket support on port 9001. Update `docker-compose.yml`:

```yaml
mqtt-broker:
  ports:
    - "1883:1883"  # MQTT
    - "9001:9001"  # WebSocket
  command: mosquitto -c /mosquitto/config/mosquitto.conf
```

## Deployment

### Option 1: Serve from Flask (Recommended)

```bash
# Build React app
cd admin-dashboard
npm run build

# Start Flask server (serves from dist/)
cd ..
python server_cyber_range.py
```

### Option 2: Separate Containers

```yaml
admin-ui:
  build:
    context: ./admin-dashboard
  ports:
    - "3000:80"
  volumes:
    - ./admin-dashboard/dist:/usr/share/nginx/html
```

## Project Structure

```
admin-dashboard/
├── src/
│   ├── components/
│   │   ├── Login.tsx           # Authentication UI
│   │   ├── Login.css
│   │   ├── Dashboard.tsx       # Main layout
│   │   ├── Dashboard.css
│   │   ├── SystemOverview.tsx  # Metrics & status
│   │   ├── SystemOverview.css
│   │   ├── PowerChart.tsx      # Chart.js graphs
│   │   ├── PowerChart.css
│   │   ├── ModbusControl.tsx   # Control interface
│   │   ├── ModbusControl.css
│   │   ├── Diagnostics.tsx     # Logs & FLAG
│   │   └── Diagnostics.css
│   ├── App.tsx                 # Root component
│   ├── App.css
│   └── main.tsx               # Entry point
├── public/
├── package.json
├── tsconfig.json
├── vite.config.ts
└── README.md
```

## Styling Guidelines

### Color Palette

- **Background**: `#0a192f` (Dark Navy)
- **Surface**: `#112240` (Navy Blue)
- **Primary**: `#64ffda` (Teal/Cyan)
- **Secondary**: `#00d4ff` (Bright Blue)
- **Success**: `#00ff88` (Green)
- **Warning**: `#ffa500` (Orange)
- **Error**: `#ff5252` (Red)
- **Text**: `#ccd6f6` (Light Blue-Gray)
- **Muted**: `#8892b0` (Gray)

### Typography

- **Headings**: `'Courier New', monospace`
- **Body**: `'Segoe UI', Tahoma, Geneva, Verdana, sans-serif`
- **Code**: `'Courier New', Courier, monospace`

## Customization

### Change MQTT Broker

Edit `src/components/Dashboard.tsx`:

```typescript
const client = mqtt.connect('ws://YOUR_BROKER_IP:9001');
```

### Change API Base URL

Edit `vite.config.ts`:

```typescript
server: {
  proxy: {
    '/api': {
      target: 'http://YOUR_API_URL',
      changeOrigin: true,
    }
  }
}
```

### Add New Metrics

Edit `src/components/SystemOverview.tsx` to add metrics cards.

## Troubleshooting

### MQTT Not Connecting

1. Check broker is running: `docker compose ps mqtt-broker`
2. Verify WebSocket port: `docker compose logs mqtt-broker`
3. Update broker config to enable WebSocket

### Login Fails

1. Check backend is running: `docker compose ps pv-controller`
2. Verify credentials: `admin:PV-Sec-2024!Admin`
3. Check API endpoint: `curl http://172.20.0.65/api/admin/login`

### Build Errors

```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install

# Check TypeScript errors
npm run build
```

## License

Part of StratoCyberLab - Educational use only
