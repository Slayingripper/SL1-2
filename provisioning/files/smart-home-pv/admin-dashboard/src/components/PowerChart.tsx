import React, { useEffect, useRef } from 'react';
import { Chart, registerables } from 'chart.js';
import { Line } from 'react-chartjs-2';
import './PowerChart.css';

Chart.register(...registerables);

interface PowerChartProps {
  telemetryData: any[];
}

const CAPACITY_KW = 4.8;
const SUNRISE_H = 6.5;
const SUNSET_H = 19.5;

/** Expected output for a given timestamp based on the site daylight model */
const expectedKw = (tsMs: number) => {
  const d = new Date(tsMs);
  const h = d.getHours() + d.getMinutes() / 60;
  if (h <= SUNRISE_H || h >= SUNSET_H) return 0;
  const x = (h - SUNRISE_H) / (SUNSET_H - SUNRISE_H);
  return Math.max(0, Math.pow(Math.sin(Math.PI * x), 1.35)) * CAPACITY_KW * 0.92;
};

const PowerChart: React.FC<PowerChartProps> = ({ telemetryData }) => {
  const chartData = {
    labels: telemetryData.map(d => {
      const date = new Date((d.timestamp || d.ts) * 1000);
      return date.toLocaleTimeString();
    }),
    datasets: [
      {
        label: 'Power Output (kW)',
        data: telemetryData.map(d => d.power_kw || d.power || d.value || 0),
        borderColor: '#ffb000',
        backgroundColor: 'rgba(255, 176, 0, 0.08)',
        tension: 0.4,
        fill: true,
        pointRadius: 0,
        pointHoverRadius: 4,
      },
      {
        label: 'Expected Output (kW)',
        data: telemetryData.map(d => expectedKw((d.timestamp || d.ts) * 1000)),
        borderColor: 'rgba(122, 162, 200, 0.8)',
        borderDash: [6, 5],
        borderWidth: 1.5,
        pointRadius: 0,
        fill: false,
        tension: 0.3,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    // Animations are disabled - the chart re-renders on every telemetry tick
    animation: false as const,
    transitions: {},
    plugins: {
      legend: {
        display: true,
        labels: {
          color: '#ffb000',
          font: {
            family: 'Courier New',
            size: 12,
          },
        },
      },
      title: {
        display: false,
      },
    },
    scales: {
      x: {
        grid: {
          color: 'rgba(100, 255, 218, 0.1)',
        },
        ticks: {
          color: '#7c8794',
          font: {
            family: 'Courier New',
          },
        },
      },
      y: {
        grid: {
          color: 'rgba(100, 255, 218, 0.1)',
        },
        ticks: {
          color: '#7c8794',
          font: {
            family: 'Courier New',
          },
        },
        beginAtZero: true,
      },
    },
  };

  const stats = {
    max: telemetryData.length > 0 ? Math.max(...telemetryData.map(d => d.power_kw || d.power || d.value || 0)) : 0,
    min: telemetryData.length > 0 ? Math.min(...telemetryData.map(d => d.power_kw || d.power || d.value || 0)) : 0,
    avg: telemetryData.length > 0
      ? telemetryData.reduce((sum, d) => sum + (d.power_kw || d.power || d.value || 0), 0) / telemetryData.length
      : 0,
  };

  const latestPower = stats.max >= 0 && telemetryData.length > 0
    ? (telemetryData[telemetryData.length - 1].power_kw ?? telemetryData[telemetryData.length - 1].power ?? 0)
    : 0;
  const latestTsMs = telemetryData.length > 0
    ? (telemetryData[telemetryData.length - 1].timestamp || telemetryData[telemetryData.length - 1].ts || Date.now() / 1000) * 1000
    : Date.now();
  const expectedNow = expectedKw(latestTsMs);
  const efficiency = expectedNow > 0.1 ? Math.min(100, Math.max(0, (latestPower / expectedNow) * 100)) : 0;
  const efficiencyDetail = efficiency >= 92 ? 'Near nominal' : efficiency >= 70 ? 'Expected for conditions' : efficiency >= 40 ? 'Derated output' : 'Below nominal';

  // Integrate the live telemetry stream (kW) to kWh earned this session
  const tariffEur = 0.15;
  let sessionKwh = 0;
  for (let i = 1; i < telemetryData.length; i++) {
    const p0 = Number(telemetryData[i - 1]?.power_kw ?? telemetryData[i - 1]?.power ?? telemetryData[i - 1]?.value ?? 0);
    const p1 = Number(telemetryData[i]?.power_kw ?? telemetryData[i]?.power ?? telemetryData[i]?.value ?? 0);
    const t0 = (telemetryData[i - 1].timestamp || telemetryData[i - 1].ts || 0) * 1000;
    const t1 = (telemetryData[i].timestamp || telemetryData[i].ts || 0) * 1000;
    sessionKwh += ((p0 + p1) / 2) * ((t1 - t0) / 3600000);
  }
  const revenue = sessionKwh * tariffEur;
  const irradiance = Math.round((latestPower / CAPACITY_KW) * 950);
  const panelTemp = Math.round(27 + irradiance / 42);

  return (
    <div className="power-chart-container">
      <div className="page-header">
        <h2>Power Analytics</h2>
        <p>Real-time power production monitoring</p>
      </div>

      <div className="stats-bar">
        <div className="stat-item">
          <span className="stat-label">Peak Power</span>
          <span className="stat-value">{stats.max.toFixed(2)} kW</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Average Power</span>
          <span className="stat-value">{stats.avg.toFixed(2)} kW</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Min Power</span>
          <span className="stat-value">{stats.min.toFixed(2)} kW</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Data Points</span>
          <span className="stat-value">{telemetryData.length}</span>
        </div>
      </div>

      <div className="chart-panel">
        <div className="chart-header">
          <h3>Power Output Over Time</h3>
          <div className="chart-controls">
            <span className="control-label">Auto-refresh: </span>
            <span className="control-status status-active">ON</span>
          </div>
        </div>
        <div className="chart-wrapper">
          {telemetryData.length > 0 ? (
            <Line data={chartData} options={options} />
          ) : (
            <div className="no-data-message">
              <div className="no-data-icon">📊</div>
              <div className="no-data-text">Waiting for telemetry data...</div>
              <div className="no-data-hint">Data will appear once MQTT telemetry is received</div>
            </div>
          )}
        </div>
      </div>

      <div className="analysis-section">
        <h3>Production Analysis</h3>
        <div className="analysis-grid">
          <div className="analysis-card">
            <div className="analysis-icon">☀️</div>
            <div className="analysis-content">
              <div className="analysis-title">Solar Irradiance</div>
              <div className="analysis-value">{irradiance} W/m²</div>
              <div className="analysis-detail">{irradiance > 700 ? 'Optimal conditions' : irradiance > 250 ? 'Partly cloudy' : 'Low light'}</div>
            </div>
          </div>
          <div className="analysis-card">
            <div className="analysis-icon">🌡️</div>
            <div className="analysis-content">
              <div className="analysis-title">Panel Temperature</div>
              <div className="analysis-value">{panelTemp}°C</div>
              <div className="analysis-detail">{panelTemp < 65 ? 'Within normal range' : 'Thermal derating likely'}</div>
            </div>
          </div>
          <div className="analysis-card">
            <div className="analysis-icon">⚙️</div>
            <div className="analysis-content">
              <div className="analysis-title">System Efficiency</div>
              <div className="analysis-value">{telemetryData.length > 0 ? efficiency.toFixed(1) : '—'}%</div>
              <div className="analysis-detail">{telemetryData.length > 0 ? efficiencyDetail : 'Waiting for telemetry'}</div>
            </div>
          </div>
          <div className="analysis-card">
            <div className="analysis-icon">💰</div>
            <div className="analysis-content">
              <div className="analysis-title">Session Revenue</div>
              <div className="analysis-value">${revenue.toFixed(2)}</div>
              <div className="analysis-detail">${tariffEur.toFixed(2)}/kWh · {sessionKwh.toFixed(2)} kWh this session</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PowerChart;
