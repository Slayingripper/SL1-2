import React, { useEffect, useRef } from 'react';
import { Chart, registerables } from 'chart.js';
import { Line } from 'react-chartjs-2';
import './PowerChart.css';

Chart.register(...registerables);

interface PowerChartProps {
  telemetryData: any[];
}

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
        borderColor: '#64ffda',
        backgroundColor: 'rgba(100, 255, 218, 0.1)',
        tension: 0.4,
        fill: true,
        pointRadius: 2,
        pointHoverRadius: 5,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        labels: {
          color: '#64ffda',
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
          color: '#8892b0',
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
          color: '#8892b0',
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
              <div className="analysis-value">875 W/m²</div>
              <div className="analysis-detail">Optimal conditions</div>
            </div>
          </div>
          <div className="analysis-card">
            <div className="analysis-icon">🌡️</div>
            <div className="analysis-content">
              <div className="analysis-title">Panel Temperature</div>
              <div className="analysis-value">42°C</div>
              <div className="analysis-detail">Within normal range</div>
            </div>
          </div>
          <div className="analysis-card">
            <div className="analysis-icon">⚙️</div>
            <div className="analysis-content">
              <div className="analysis-title">System Efficiency</div>
              <div className="analysis-value">94.2%</div>
              <div className="analysis-detail">Above average</div>
            </div>
          </div>
          <div className="analysis-card">
            <div className="analysis-icon">💰</div>
            <div className="analysis-content">
              <div className="analysis-title">Today's Revenue</div>
              <div className="analysis-value">$12.45</div>
              <div className="analysis-detail">$0.15/kWh rate</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PowerChart;
