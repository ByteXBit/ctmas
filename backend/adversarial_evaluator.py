import torch
import numpy as np

class AdversarialEvaluator:
    def __init__(self, model):
        self.model = model
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.model.eval()

    def _get_loss(self, x):
        recon, _ = self.model(x)
        return torch.mean((x - recon) ** 2)

    def fgsm_attack(self, x_orig, eps):
        x = x_orig.clone().detach().to(self.device).requires_grad_(True)
        loss = self._get_loss(x)
        
        self.model.zero_grad()
        loss.backward()
        
        data_grad = x.grad.data
        # Minimize reconstruction error to evade detection
        x_adv = x - eps * data_grad.sign()
        
        with torch.no_grad():
            adv_loss = self._get_loss(x_adv).item()
            
        return x_adv.detach(), adv_loss

    def pgd_attack(self, x_orig, eps, iters=40):
        x = x_orig.clone().detach().to(self.device)
        alpha = eps / 20.0
        
        for _ in range(iters):
            x.requires_grad_(True)
            loss = self._get_loss(x)
            
            self.model.zero_grad()
            loss.backward()
            
            data_grad = x.grad.data
            with torch.no_grad():
                x = x - alpha * data_grad.sign()
                eta = torch.clamp(x - x_orig, min=-eps, max=eps)
                x = torch.clamp(x_orig + eta, min=-5.0, max=5.0) # assuming normalized features ~ [-5, 5]
                
        with torch.no_grad():
            adv_loss = self._get_loss(x).item()
            
        return x.detach(), adv_loss

    def tpa_attack(self, x_orig, shift):
        # Roll along time axis (dim 1)
        x_adv = torch.roll(x_orig, shifts=shift, dims=1)
        with torch.no_grad():
            adv_loss = self._get_loss(x_adv).item()
        return x_adv, adv_loss

    def evaluate(self, window_data, eps=0.10, threshold=0.5):
        # window_data: shape [30, 20]
        x_orig = torch.tensor(window_data, dtype=torch.float32).unsqueeze(0).to(self.device)
        
        with torch.no_grad():
            orig_loss = self._get_loss(x_orig).item()
            
        report = {
            "baseline_error": float(orig_loss),
            "threshold": float(threshold),
            "attacks": []
        }
        
        evasion_fgsm = False
        evasion_pgd = False
        
        # FGSM tests
        for e in [0.05, 0.10, 0.20]:
            _, adv_loss = self.fgsm_attack(x_orig, e)
            pct_red = (orig_loss - adv_loss) / orig_loss if orig_loss > 0 else 0
            evasion = adv_loss < threshold
            if evasion: evasion_fgsm = True
            
            report["attacks"].append({
                "type": "FGSM",
                "epsilon": e,
                "adv_error": float(adv_loss),
                "reduction_pct": float(pct_red * 100.0),
                "evasion_succeeded": bool(evasion)
            })

        # PGD tests
        for e in [0.05, 0.10]:
            _, adv_loss = self.pgd_attack(x_orig, e)
            pct_red = (orig_loss - adv_loss) / orig_loss if orig_loss > 0 else 0
            evasion = adv_loss < threshold
            if evasion: evasion_pgd = True
            
            report["attacks"].append({
                "type": "PGD",
                "epsilon": e,
                "adv_error": float(adv_loss),
                "reduction_pct": float(pct_red * 100.0),
                "evasion_succeeded": bool(evasion)
            })
            
        # TPA tests
        for s in [1, 3]:
            _, adv_loss = self.tpa_attack(x_orig, s)
            pct_red = (orig_loss - adv_loss) / orig_loss if orig_loss > 0 else 0
            evasion = adv_loss < threshold
            
            report["attacks"].append({
                "type": "TPA",
                "shift": s,
                "adv_error": float(adv_loss),
                "reduction_pct": float(pct_red * 100.0),
                "evasion_succeeded": bool(evasion)
            })

        if not evasion_fgsm and not evasion_pgd:
            vuln_level = "LOW"
        elif evasion_fgsm and evasion_pgd:
            vuln_level = "HIGH"
        else:
            vuln_level = "MEDIUM"
            
        report["vulnerability_level"] = vuln_level
        return report
