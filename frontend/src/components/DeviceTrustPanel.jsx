import React, { useEffect, useState } from 'react';

const DeviceTrustPanel = () => {
    const [devices, setDevices] = useState([]);

    useEffect(() => {
        const fetchState = async () => {
            try {
                const res = await fetch('/api/threat-model-state');
                if (res.ok) {
                    const data = await res.json();
                    setDevices(data);
                }
            } catch (err) {
                console.error("Failed to fetch threat state", err);
            }
        };

        const interval = setInterval(fetchState, 2000);
        fetchState();
        return () => clearInterval(interval);
    }, []);

    const getTrustColor = (score) => {
        if (score > 0.7) return '#3fb950';    // Green
        if (score >= 0.3) return '#d29922';   // Yellow
        return '#f85149';                     // Red
    };

    return (
        <div className="glass-panel">
            <h2>Device Trust State</h2>
            <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                        <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                            <th style={{ padding: '8px' }}>Device ID</th>
                            <th style={{ padding: '8px' }}>Trust Score</th>
                            <th style={{ padding: '8px' }}>Status</th>
                            <th style={{ padding: '8px' }}>UTS</th>
                            <th style={{ padding: '8px' }}>Last Alert</th>
                            <th style={{ padding: '8px' }}>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {devices.map(dev => {
                            const uts = dev.uts_history && dev.uts_history.length > 0 
                                ? dev.uts_history[dev.uts_history.length - 1].toFixed(1)
                                : '0.0';
                                
                            const isQuarantined = dev.trust_score < 0.1 || dev.status === 'quarantined';
                            
                            return (
                                <tr key={dev.device_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                    <td style={{ padding: '8px' }}>{dev.device_id}</td>
                                    <td style={{ padding: '8px', color: getTrustColor(dev.trust_score), fontWeight: 'bold' }}>
                                        {dev.trust_score.toFixed(2)}
                                    </td>
                                    <td style={{ padding: '8px' }}>
                                        {isQuarantined ? <span style={{ color: '#f85149' }}>Quarantined</span> : dev.status}
                                    </td>
                                    <td style={{ padding: '8px' }}>{uts}</td>
                                    <td style={{ padding: '8px', fontSize: '0.85rem' }}>
                                        {dev.last_alert_time ? new Date(dev.last_alert_time).toLocaleTimeString() : 'N/A'}
                                    </td>
                                    <td style={{ padding: '8px' }}>
                                        {!isQuarantined && dev.trust_score < 0.1 && (
                                            <button 
                                                style={{ 
                                                    background: '#f85149', 
                                                    border: 'none', 
                                                    color: '#fff', 
                                                    padding: '4px 8px', 
                                                    borderRadius: '4px',
                                                    cursor: 'pointer'
                                                }}
                                            >
                                                Quarantine
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
                {devices.length === 0 && (
                    <p style={{ color: 'var(--text-secondary)', padding: '8px' }}>No active devices.</p>
                )}
            </div>
        </div>
    );
};

export default DeviceTrustPanel;
