import torch
import torch.nn as nn
import numpy as np
from collections import deque
import json
import os

class HybridLSTMAE(nn.Module):
    def __init__(self, input_dim=20, window=30, forecast_steps=5):
        super(HybridLSTMAE, self).__init__()
        self.window = window
        self.forecast_steps = forecast_steps
        self.input_dim = input_dim

        # Encoder
        self.e1 = nn.LSTM(input_dim, 64, batch_first=True, bidirectional=True)
        self.bn1 = nn.BatchNorm1d(window)
        self.drop1 = nn.Dropout(0.2)
        
        self.e2 = nn.LSTM(128, 32, batch_first=True, bidirectional=True)
        self.bn2 = nn.BatchNorm1d(window)
        self.drop2 = nn.Dropout(0.2)
        
        self.e3 = nn.LSTM(64, 16, batch_first=True, bidirectional=True)
        self.bn3 = nn.BatchNorm1d(window)
        
        # Reconstruction Head
        self.r1 = nn.LSTM(32, 64, batch_first=True)
        self.r2 = nn.LSTM(64, 128, batch_first=True)
        self.drop_r2 = nn.Dropout(0.2)
        self.r3 = nn.Linear(128, input_dim)
        
        # Forecast Head
        self.f1 = nn.Linear(32, 64)
        self.f_relu = nn.ReLU()
        self.f_drop = nn.Dropout(0.2)  # For MC Dropout
        self.f2 = nn.Linear(64, forecast_steps * input_dim)

        self.apply(self._init_weights)
        
        self.clean_scores = deque(maxlen=300) # 5-minute window if 1 score per sec

    def _init_weights(self, m):
        if isinstance(m, nn.Linear):
            nn.init.xavier_uniform_(m.weight)
            if m.bias is not None:
                nn.init.zeros_(m.bias)
        elif isinstance(m, nn.LSTM):
            for name, param in m.named_parameters():
                if 'weight_ih' in name:
                    nn.init.xavier_uniform_(param.data)
                elif 'weight_hh' in name:
                    nn.init.orthogonal_(param.data)
                elif 'bias' in name:
                    nn.init.zeros_(param.data)

    def forward(self, x):
        # x: [batch, 30, 20]
        # Encoder
        e1_out, _ = self.e1(x)
        e1_out = self.bn1(e1_out)
        e1_out = self.drop1(e1_out)
        
        e2_out, _ = self.e2(e1_out)
        e2_out = self.bn2(e2_out)
        e2_out = self.drop2(e2_out)
        
        e3_out, (hn, cn) = self.e3(e2_out)
        # hn shape: [2, batch, 16] -> concat -> [batch, 32]
        z = torch.cat((hn[-2,:,:], hn[-1,:,:]), dim=1)
        
        # Reconstruction
        # Duplicate z to window size
        z_rep = z.unsqueeze(1).repeat(1, self.window, 1)
        r1_out, _ = self.r1(z_rep)
        r2_out, _ = self.r2(r1_out)
        r2_out = self.drop_r2(r2_out)
        reconstruction = self.r3(r2_out)
        
        return reconstruction, z

    def reconstruction_error(self, x):
        self.eval()
        with torch.no_grad():
            recon, _ = self.forward(x)
            mse = torch.mean((x - recon) ** 2, dim=[1, 2])
        return mse

    def forecast(self, x, passes=20):
        # Enable dropout for MC Dropout
        self.train()
        with torch.no_grad():
            _, z = self.forward(x)
            preds = []
            for _ in range(passes):
                h = self.f_relu(self.f1(z))
                h = self.f_drop(h)
                out = self.f2(h).view(-1, self.forecast_steps, self.input_dim)
                preds.append(out.unsqueeze(0))
            
            preds = torch.cat(preds, dim=0) # [passes, batch, 5, 20]
            mean_pred = torch.mean(preds, dim=0)
            std_pred = torch.std(preds, dim=0)
            
        self.eval()
        return mean_pred, std_pred

    def anomaly_score(self, x, threshold, device_id, norm_stats_path="ml/norm_stats.json"):
        # returns dict
        mse = self.reconstruction_error(x).item()
        
        # load stats to denormalize predictions
        mean_stat = np.zeros(self.input_dim)
        std_stat = np.ones(self.input_dim)
        if os.path.exists(norm_stats_path):
            with open(norm_stats_path, 'r') as f:
                stats = json.load(f)
                if device_id in stats:
                    mean_stat = np.array(stats[device_id]['mean'])
                    std_stat = np.sqrt(np.array(stats[device_id]['var'])) + 1e-6
        
        mean_pred, std_pred = self.forecast(x)
        mean_pred = mean_pred[0].cpu().numpy()
        std_pred = std_pred[0].cpu().numpy()
        
        upper_bound = mean_pred + 1.96 * std_pred
        # Denormalize
        upper_bound_denorm = upper_bound * std_stat + mean_stat
        mean_pred_denorm = mean_pred * std_stat + mean_stat
        
        predictive_alert = False
        
        # hr_bpm
        if np.any(upper_bound_denorm[:, 0] > 150) or np.any(upper_bound_denorm[:, 0] < 40): predictive_alert = True
        # spo2
        if np.any(upper_bound_denorm[:, 1] < 90): predictive_alert = True
        # rr
        if np.any(upper_bound_denorm[:, 2] > 30) or np.any(upper_bound_denorm[:, 2] < 6): predictive_alert = True
        # sbp
        if np.any(upper_bound_denorm[:, 3] > 180) or np.any(upper_bound_denorm[:, 3] < 80): predictive_alert = True
        # ecg mean > 3 std from baseline. Since normalized, > 3 means standard deviation > 3. 
        if np.any(np.abs(upper_bound[:, 5]) > 3): predictive_alert = True
        
        # score scaling
        score_lstm = min(35.0, (mse / max(threshold, 1e-6)) * 35.0)
        score_pred = 25.0 if predictive_alert else 0.0
        
        is_anomaly = (mse > threshold)
        
        # top 3 features by MSE
        recon, _ = self.forward(x)
        feat_mse = torch.mean((x - recon)**2, dim=1)[0].detach().cpu().numpy()
        top3_idx = np.argsort(feat_mse)[-3:][::-1]
        
        feature_names = ["hr_bpm", "spo2_pct", "rr_bpm", "sbp_mmhg", "dbp_mmhg", 
                        "ecg_mean", "ecg_std", "ecg_min", "ecg_max", "ecg_slope", 
                        "ecg_zero_crossing_rate", "ecg_approx_entropy", "ecg_spectral_entropy",
                        "tx_interval_ms", "payload_bytes", "interval_jitter",
                        "correlation_deviation", "sqi_slope", "payload_hash_entropy", "ip_entropy"]
        top3_features = [feature_names[i] for i in top3_idx]
        
        return {
            'score_lstm': float(score_lstm),
            'score_pred': float(score_pred),
            'is_anomaly': bool(is_anomaly),
            'predictive_alert': bool(predictive_alert),
            'top3_features': top3_features,
            'mse': float(mse),
            'forecast_points': mean_pred_denorm.tolist(),
            'forecast_ci': upper_bound_denorm.tolist()
        }
