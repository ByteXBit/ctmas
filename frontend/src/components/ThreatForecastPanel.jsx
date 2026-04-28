import React, { useEffect, useState } from 'react';
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement,
  LineElement, Title, Tooltip, Legend, Filler, ArcElement
} from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler, ArcElement);

const ThreatForecastPanel = () => {
  const [data, setData] = useState({
    forecast: [], forecast_ci: [], predictive_alert: false,
    uts: 0.0, severity: "NOMINAL", action: "none",
    attack_class: null, mitre_id: null,
    s_iso: 0.0, s_lstm: 0.0, s_pred: 0.0,
    trust_score: 1.0, last_updated: null,
  });
  const [resilience, setResilience] = useState({
    total_ticks: 0, attack_ticks: 0, normal_ticks: 0,
    uptime_pct: 100, avg_uts: 0, resilience_score: 100,
  });

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [dashRes, resRes] = await Promise.all([
          fetch('/api/dashboard'),
          fetch('/api/resilience'),
        ]);
        if (dashRes.ok) setData(await dashRes.json());
        if (resRes.ok) setResilience(await resRes.json());
      } catch (err) { /* silent */ }
    };
    const id = setInterval(fetchAll, 1000);
    fetchAll();
    return () => clearInterval(id);
  }, []);

  const severityColor = {
    NOMINAL: '#3fb950', ADVISORY: '#58a6ff',
    WARNING: '#d29922', THREAT: '#f85149', CRITICAL: '#ff4444'
  }[data.severity] || '#888';

  const utsGaugeData = {
    datasets: [{
      data: [data.uts, 100 - data.uts],
      backgroundColor: [severityColor, 'rgba(255,255,255,0.07)'],
      borderWidth: 0,
      circumference: 180,
      rotation: 270,
    }]
  };
  const utsGaugeOptions = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { enabled: false } },
    cutout: '75%',
  };

  const hrForecast = data.forecast?.map?.(s => s[0]) ?? [];
  const hrCI = data.forecast_ci?.map?.(s => s[0]) ?? [];
  const chartLabels = ['t+1', 't+2', 't+3', 't+4', 't+5'];

  const forecastChartData = {
    labels: chartLabels,
    datasets: [
      {
        label: '95% CI',
        data: hrCI.length ? hrCI : Array(5).fill(null),
        borderColor: 'rgba(248,81,73,0.35)',
        backgroundColor: 'rgba(248,81,73,0.07)',
        fill: true, borderWidth: 1, pointRadius: 0, tension: 0.4,
      },
      {
        label: 'Predicted HR',
        data: hrForecast.length ? hrForecast : Array(5).fill(null),
        borderColor: '#3fb950', borderWidth: 2,
        tension: 0.4, fill: false, pointRadius: 3,
      },
      {
        label: 'Alarm (150)',
        data: Array(5).fill(150),
        borderColor: 'rgba(248,81,73,0.7)',
        borderWidth: 1.5, borderDash: [5, 5],
        pointRadius: 0, tension: 0, fill: false,
      }
    ]
  };
  const forecastChartOptions = {
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 300 },
    scales: {
      y: { suggestedMin: 50, suggestedMax: 170, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e' } },
      x: { grid: { display: false }, ticks: { color: '#8b949e' } },
    },
    plugins: { legend: { display: false } }
  };

  const scoreBar = (label, val, max, color) => (
    <div style={{ marginBottom: '10px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', color: '#8b949e', marginBottom: '4px' }}>
        <span>{label}</span><span style={{ color }}>{val.toFixed(1)} / {max}</span>
      </div>
      <div style={{ background: 'rgba(255,255,255,0.07)', borderRadius: '4px', height: '6px', overflow: 'hidden' }}>
        <div style={{ width: `${Math.min(100, (val / max) * 100).toFixed(1)}%`, background: color, height: '100%', borderRadius: '4px', transition: 'width 0.4s' }} />
      </div>
    </div>
  );

  const actionBadge = {
    none: { label: 'No Action', color: '#3fb950' },
    increase_sampling: { label: '↑ Sampling Rate', color: '#58a6ff' },
    rate_limit: { label: '⚠ Rate Limited', color: '#d29922' },
    suspend_30s: { label: '⏸ Suspended 30s', color: '#f85149' },
    terminate_session: { label: '🛑 Session Terminated', color: '#ff4444' },
  }[data.action] || { label: data.action, color: '#888' };

  return (
    <div style={{ display: 'contents' }}>
      {/* UTS Gauge */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <h2 style={{ alignSelf: 'flex-start' }}>Unified Threat Score</h2>
        <div style={{ position: 'relative', width: '200px', height: '110px', marginTop: '8px' }}>
          <Doughnut data={utsGaugeData} options={utsGaugeOptions} />
          <div style={{ position: 'absolute', bottom: '0', left: '50%', transform: 'translateX(-50%)', textAlign: 'center' }}>
            <div style={{ fontSize: '2rem', fontWeight: '700', color: severityColor, lineHeight: 1 }}>{data.uts.toFixed(1)}</div>
            <div style={{ fontSize: '0.75rem', color: '#8b949e' }}>/ 100</div>
          </div>
        </div>
        <div style={{ marginTop: '12px', textAlign: 'center' }}>
          <span style={{ background: severityColor + '22', color: severityColor, padding: '3px 12px', borderRadius: '12px', fontSize: '0.85rem', fontWeight: 600 }}>
            {data.severity}
          </span>
        </div>
        <div style={{ marginTop: '8px', fontSize: '0.8rem', color: actionBadge.color, background: actionBadge.color + '15', padding: '4px 10px', borderRadius: '8px' }}>
          {actionBadge.label}
        </div>
        <div style={{ width: '100%', marginTop: '16px' }}>
          {scoreBar('Isolation Score (S_iso)', data.s_iso, 40, '#58a6ff')}
          {scoreBar('LSTM Anomaly (S_lstm)', data.s_lstm, 35, '#d29922')}
          {scoreBar('Predictive Risk (S_pred)', data.s_pred, 25, '#f85149')}
        </div>
        <div style={{ width: '100%', marginTop: '8px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
          <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: '8px', padding: '8px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.7rem', color: '#8b949e' }}>Trust Score</div>
            <div style={{ fontWeight: 700, color: data.trust_score > 0.7 ? '#3fb950' : data.trust_score > 0.3 ? '#d29922' : '#f85149' }}>
              {(data.trust_score * 100).toFixed(0)}%
            </div>
          </div>
          <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: '8px', padding: '8px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.7rem', color: '#8b949e' }}>Alert</div>
            <div style={{ fontWeight: 700, color: data.predictive_alert ? '#f85149' : '#3fb950' }}>
              {data.predictive_alert ? '⚡ PREDICTED' : '✓ Normal'}
            </div>
          </div>
        </div>
        {data.attack_class && (
          <div style={{ marginTop: '12px', width: '100%', background: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.3)', borderRadius: '8px', padding: '8px' }}>
            <div style={{ fontSize: '0.7rem', color: '#8b949e' }}>Detected Attack</div>
            <div style={{ fontWeight: 600, color: '#f85149', fontSize: '0.85rem' }}>{data.attack_class}</div>
            <div style={{ fontSize: '0.72rem', color: '#8b949e' }}>MITRE: {data.mitre_id}</div>
          </div>
        )}
      </div>

      {/* HR Forecast Chart */}
      <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
        <h2>Heart Rate Forecast</h2>
        <p style={{ fontSize: '0.8rem', color: '#8b949e', margin: '0 0 12px 0' }}>
          MC-Dropout 5-step prediction with 95% confidence interval
        </p>
        <div style={{ flex: 1, minHeight: '180px' }}>
          {hrForecast.length > 0 ? (
            <Line data={forecastChartData} options={forecastChartOptions} style={{ height: '100%' }} />
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#8b949e', fontSize: '0.85rem' }}>
              ⏳ Buffering 30 readings before forecast is available…
            </div>
          )}
        </div>

        {/* Resilience Stats */}
        <div style={{ marginTop: '16px', borderTop: '1px solid rgba(255,255,255,0.07)', paddingTop: '14px' }}>
          <div style={{ fontSize: '0.8rem', color: '#8b949e', marginBottom: '10px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Session Resilience
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
            {[
              { label: 'Total Ticks', val: resilience.total_ticks },
              { label: 'Attack Ticks', val: resilience.attack_ticks, danger: resilience.attack_ticks > 0 },
              { label: 'Uptime', val: `${resilience.uptime_pct}%`, ok: resilience.uptime_pct >= 90 },
              { label: 'Avg UTS', val: resilience.avg_uts?.toFixed?.(1) ?? '0.0' },
              { label: 'Normal Ticks', val: resilience.normal_ticks },
              { label: 'Resilience', val: `${resilience.resilience_score}%`, ok: resilience.resilience_score >= 80 },
            ].map(({ label, val, danger, ok }) => (
              <div key={label} style={{ background: 'rgba(255,255,255,0.04)', borderRadius: '8px', padding: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: '0.67rem', color: '#8b949e' }}>{label}</div>
                <div style={{ fontWeight: 700, fontSize: '0.95rem', color: danger ? '#f85149' : ok ? '#3fb950' : '#e6edf3' }}>{val}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatForecastPanel;
