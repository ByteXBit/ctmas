import { useEffect, useState } from 'react'
import {
  Chart as ChartJS, CategoryScale, LinearScale,
  PointElement, LineElement, Title, Tooltip, Legend, Filler, ArcElement
} from 'chart.js'
import { Line, Doughnut } from 'react-chartjs-2'
import DeviceTrustPanel from './components/DeviceTrustPanel'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler, ArcElement)

// ─── helpers ──────────────────────────────────────────────────────────────────
const SEV_COLOR = { NOMINAL: '#3fb950', ADVISORY: '#58a6ff', WARNING: '#d29922', THREAT: '#f85149', CRITICAL: '#ff4444' }
const ACTION_LABEL = {
  none:              { label: 'No Action Required', color: '#3fb950' },
  increase_sampling: { label: '↑ Sampling Rate',   color: '#58a6ff' },
  rate_limit:        { label: '⚠ Rate Limited',     color: '#d29922' },
  suspend_30s:       { label: '⏸ Suspended 30s',    color: '#f85149' },
  terminate_session: { label: '🛑 Session Terminated', color: '#ff4444' },
}
const sc = (v, d, w) => v >= d ? 'status-danger' : v >= w ? 'status-warning' : 'status-normal'

function ScoreBar({ label, val, max, color }) {
  const pct = Math.min(100, (val / max) * 100)
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', color: '#8b949e', marginBottom: 3 }}>
        <span>{label}</span><span style={{ color }}>{val.toFixed(1)} / {max}</span>
      </div>
      <div style={{ background: 'rgba(255,255,255,0.07)', borderRadius: 4, height: 6 }}>
        <div style={{ width: `${pct}%`, background: color, height: '100%', borderRadius: 4, transition: 'width 0.4s' }} />
      </div>
    </div>
  )
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [incidents, setIncidents] = useState([])
  const [dash, setDash] = useState({
    uts: 0, severity: 'NOMINAL', trust_score: 1, predictive_alert: false,
    attack_class: null, mitre_id: null, s_iso: 0, s_lstm: 0, s_pred: 0,
    action: 'none', forecast: [], forecast_ci: [],
  })
  const [resilience, setResilience] = useState({ total_ticks: 0, attack_ticks: 0, uptime_pct: 100, avg_uts: 0, resilience_score: 100 })
  const [status, setStatus] = useState({ threat_type: 'Secure', anomaly_score: 0, risk_score: 0 })
  const [ecgData, setEcgData] = useState(Array(250).fill(0))

  // Poll incidents
  useEffect(() => {
    const fetch_ = async () => {
      try {
        const r = await fetch('/incidents')
        if (!r.ok) return
        const data = await r.json()
        setIncidents(data)
        if (data.length > 0) {
          const l = data[0]
          if (Date.now() - new Date(l.timestamp).getTime() < 5000) {
            setStatus({ threat_type: l.threat_type, anomaly_score: l.anomaly_score, risk_score: l.risk_score })
          } else {
            setStatus({ threat_type: 'Secure', anomaly_score: 0, risk_score: 0 })
          }
        }
      } catch {}
    }
    const id = setInterval(fetch_, 2000); fetch_(); return () => clearInterval(id)
  }, [])

  // Poll dashboard & resilience
  useEffect(() => {
    const fetch_ = async () => {
      try {
        const [dr, rr] = await Promise.all([fetch('/api/dashboard'), fetch('/api/resilience')])
        if (dr.ok) setDash(await dr.json())
        if (rr.ok) setResilience(await rr.json())
      } catch {}
    }
    const id = setInterval(fetch_, 1000); fetch_(); return () => clearInterval(id)
  }, [])

  // Live ECG waveform
  useEffect(() => {
    let t = 0
    const id = setInterval(() => {
      setEcgData(prev => {
        const n = [...prev.slice(1)]
        const c = t % 100
        let v = c===10?.5:c===30?-.5:c===32?2.5:c===35?-1:c===60?.7:(Math.random()-.5)*.1
        if (status.threat_type.includes('injection')) v += (Math.random()-.5)*5
        if (status.threat_type.includes('dos') || status.threat_type.includes('DoS')) v = 0
        n.push(v); t++; return n
      })
    }, 20)
    return () => clearInterval(id)
  }, [status.threat_type])

  const sevColor = SEV_COLOR[dash.severity] || '#888'
  const actionInfo = ACTION_LABEL[dash.action] || { label: dash.action, color: '#888' }
  const ecgColor = status.threat_type === 'Secure' ? '#3fb950' : '#f85149'

  // ── ECG chart ──
  const ecgChart = {
    labels: ecgData.map((_, i) => i),
    datasets: [{ label: 'ECG', data: ecgData, borderColor: ecgColor, backgroundColor: ecgColor+'18', borderWidth: 2, pointRadius: 0, tension: 0.4, fill: true }]
  }
  const ecgOpts = {
    responsive: true, maintainAspectRatio: false, animation: { duration: 0 },
    scales: { x: { display: false }, y: { suggestedMin: -3, suggestedMax: 4, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8b949e' } } },
    plugins: { legend: { display: false }, tooltip: { enabled: false } }
  }

  // ── UTS gauge ──
  const gaugeData = {
    datasets: [{ data: [dash.uts, 100-dash.uts], backgroundColor: [sevColor, 'rgba(255,255,255,0.07)'], borderWidth: 0, circumference: 180, rotation: 270 }]
  }
  const gaugeOpts = { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { enabled: false } }, cutout: '75%' }

  // ── HR Forecast chart ──
  const hrForecast = dash.forecast?.map?.(s => Array.isArray(s) ? s[0] : s) ?? []
  const hrCI      = dash.forecast_ci?.map?.(s => Array.isArray(s) ? s[0] : s) ?? []
  const forecastChart = {
    labels: ['t+1','t+2','t+3','t+4','t+5'],
    datasets: [
      { label:'95% CI', data: hrCI.length ? hrCI : Array(5).fill(null), borderColor:'rgba(248,81,73,0.3)', backgroundColor:'rgba(248,81,73,0.07)', fill:true, borderWidth:1, pointRadius:0, tension:0.4 },
      { label:'Predicted HR', data: hrForecast.length ? hrForecast : Array(5).fill(null), borderColor:'#3fb950', borderWidth:2, tension:0.4, fill:false, pointRadius:3 },
      { label:'Alarm (150)', data: Array(5).fill(150), borderColor:'rgba(248,81,73,0.6)', borderWidth:1.5, borderDash:[5,5], pointRadius:0, fill:false },
    ]
  }
  const forecastOpts = {
    responsive: true, maintainAspectRatio: false, animation: { duration: 300 },
    scales: {
      y: { suggestedMin: 50, suggestedMax: 170, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color:'#8b949e' } },
      x: { grid: { display: false }, ticks: { color:'#8b949e' } }
    },
    plugins: { legend: { display: false } }
  }

  return (
    <div className="dashboard-container">

      {/* ── Header ── */}
      <div className="header full-width" style={{ gridColumn: '1 / -1' }}>
        <h1>Cardiac CPS — Adaptive Threat Modeling Dashboard</h1>
      </div>

      {/* ── ECG Stream ── */}
      <div className="glass-panel" style={{ gridColumn: '1 / 2', display: 'flex', flexDirection: 'column' }}>
        <h2><span className="pulse" style={{ background: ecgColor }}></span>&nbsp; Live ECG Stream</h2>
        <div className="chart-container"><Line data={ecgChart} options={ecgOpts} /></div>
      </div>

      {/* ── Security Posture ── */}
      <div className="glass-panel" style={{ gridColumn: '2 / 3' }}>
        <h2>Security Posture</h2>
        <div className="metrics-grid">
          {[
            { label: 'Threat Class',    val: status.threat_type,                        cls: status.threat_type==='Secure'?'status-normal':'status-danger', raw: true },
            { label: 'Anomaly Score',  val: status.anomaly_score.toFixed(2),             cls: sc(status.anomaly_score,0.7,0.4) },
            { label: 'Risk Score',     val: (status.risk_score*100).toFixed(1)+'%',      cls: sc(status.risk_score,0.8,0.4) },
            { label: 'UTS Score',      val: (dash.uts||0).toFixed(1),                   cls: dash.uts>=61?'status-danger':dash.uts>=41?'status-warning':'status-normal' },
            { label: 'Device Trust',   val: ((dash.trust_score||1)*100).toFixed(0)+'%', cls: dash.trust_score>0.7?'status-normal':dash.trust_score>0.3?'status-warning':'status-danger' },
            { label: 'Pred Alert',     val: dash.predictive_alert?'⚡ YES':'✓ None',     cls: dash.predictive_alert?'status-danger':'status-normal' },
          ].map(({ label, val, cls }) => (
            <div key={label} className={`metric-card ${cls}`}>
              <span className="metric-label">{label}</span>
              <span className="metric-value" style={{ fontSize: '1.3rem' }}>{val}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── UTS Gauge ── */}
      <div className="glass-panel" style={{ gridColumn: '3 / 4', display:'flex', flexDirection:'column', alignItems:'center' }}>
        <h2 style={{ alignSelf:'flex-start' }}>Unified Threat Score</h2>
        <div style={{ position:'relative', width:180, height:100, marginTop:8 }}>
          <Doughnut data={gaugeData} options={gaugeOpts} />
          <div style={{ position:'absolute', bottom:0, left:'50%', transform:'translateX(-50%)', textAlign:'center' }}>
            <div style={{ fontSize:'1.8rem', fontWeight:700, color:sevColor, lineHeight:1 }}>{(dash.uts||0).toFixed(1)}</div>
            <div style={{ fontSize:'0.7rem', color:'#8b949e' }}>/ 100</div>
          </div>
        </div>
        <span style={{ marginTop:8, background:sevColor+'22', color:sevColor, padding:'2px 14px', borderRadius:12, fontSize:'0.82rem', fontWeight:600 }}>{dash.severity}</span>
        <span style={{ marginTop:6, fontSize:'0.78rem', color:actionInfo.color, background:actionInfo.color+'15', padding:'3px 10px', borderRadius:8 }}>{actionInfo.label}</span>
        <div style={{ width:'100%', marginTop:14 }}>
          <ScoreBar label="S_iso (Isolation)"  val={dash.s_iso||0}  max={40} color="#58a6ff" />
          <ScoreBar label="S_lstm (LSTM)"      val={dash.s_lstm||0} max={35} color="#d29922" />
          <ScoreBar label="S_pred (Forecast)"  val={dash.s_pred||0} max={25} color="#f85149" />
        </div>
        {dash.attack_class && (
          <div style={{ marginTop:10, width:'100%', background:'rgba(248,81,73,0.1)', border:'1px solid rgba(248,81,73,0.3)', borderRadius:8, padding:'8px 10px' }}>
            <div style={{ fontSize:'0.67rem', color:'#8b949e' }}>Detected Attack</div>
            <div style={{ fontWeight:600, color:'#f85149', fontSize:'0.83rem' }}>{dash.attack_class}</div>
            <div style={{ fontSize:'0.7rem', color:'#8b949e' }}>MITRE: {dash.mitre_id}</div>
          </div>
        )}
      </div>

      {/* ── HR Forecast ── */}
      <div className="glass-panel" style={{ gridColumn: '1 / 3', display:'flex', flexDirection:'column' }}>
        <h2>Heart Rate Forecast (MC-Dropout, 5-step)</h2>
        <div style={{ flex:1, minHeight:180 }}>
          {hrForecast.length > 0
            ? <Line data={forecastChart} options={forecastOpts} style={{ height:'100%' }} />
            : <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:180, color:'#8b949e', fontSize:'0.85rem' }}>
                ⏳ Buffering — forecast appears after 30 readings (~60 s)…
              </div>
          }
        </div>
      </div>

      {/* ── Resilience Stats ── */}
      <div className="glass-panel" style={{ gridColumn: '3 / 4' }}>
        <h2>Session Resilience</h2>
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
          {[
            { label:'Total Ticks',   val: resilience.total_ticks },
            { label:'Attack Ticks',  val: resilience.attack_ticks,   danger: resilience.attack_ticks>0 },
            { label:'Uptime',        val: `${resilience.uptime_pct}%`,  ok: resilience.uptime_pct>=90 },
            { label:'Avg UTS',       val: (resilience.avg_uts||0).toFixed?.(1) },
            { label:'Normal Ticks',  val: resilience.normal_ticks },
            { label:'Resilience',    val: `${resilience.resilience_score}%`, ok: resilience.resilience_score>=80 },
          ].map(({ label, val, danger, ok }) => (
            <div key={label} style={{ background:'rgba(255,255,255,0.04)', borderRadius:8, padding:'8px 10px', textAlign:'center' }}>
              <div style={{ fontSize:'0.67rem', color:'#8b949e' }}>{label}</div>
              <div style={{ fontWeight:700, fontSize:'0.95rem', color: danger?'#f85149':ok?'#3fb950':'#e6edf3' }}>{val}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Device Trust ── */}
      <div style={{ gridColumn: '1 / -1' }}>
        <DeviceTrustPanel />
      </div>

      {/* ── Event Log ── */}
      <div className="glass-panel" style={{ gridColumn: '1 / -1' }}>
        <h2>Security Event Log</h2>
        <div className="incidents-list">
          {incidents.length === 0
            ? <p style={{ color:'var(--text-secondary)' }}>System secure — no threats detected.</p>
            : incidents.map(inc => (
              <div key={inc.id} className="incident-item">
                <div className="incident-header">
                  <span className={`incident-type ${inc.risk_score>0.8?'':'warning'}`}>{inc.threat_type}</span>
                  <span style={{ fontSize:'0.75rem', color:'#8b949e' }}>
                    Risk {(inc.risk_score*100).toFixed(1)}% &nbsp;|&nbsp; Anomaly {inc.anomaly_score.toFixed(2)}
                  </span>
                  <span className="incident-time">{new Date(inc.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="incident-explanation">
                  <div className="rag-badge">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    Adaptive Response
                  </div>
                  <p>{inc.mitigation_action}</p>
                  <p style={{ fontSize:'0.78rem', color:'var(--text-secondary)', marginTop:4 }}>Device: {inc.device_id}</p>
                </div>
              </div>
            ))
          }
        </div>
      </div>
    </div>
  )
}
