import faiss
import numpy as np

class FAISSRAGGenerator:
    def __init__(self):
        # Setup a basic FAISS index for retrieving context
        # In a real system, texts would be embedded with an LLM (e.g., SentenceTransformers)
        self.explanations = [
            "The ECG signal exhibits normal sinus rhythm. No immediate risk detected.",
            "Premature Atrial Contraction detected. Usually benign but warrants monitoring if frequent.",
            "Premature Ventricular Contraction detected. May indicate underlying structural heart disease. Requires evaluation.",
            "Irregular and often very rapid heart rhythm. High risk of stroke and heart failure. Immediate medical attention required."
        ]
        self.arrhythmia_keys = ["Normal", "PAC", "PVC", "Atrial Fibrillation"]
        
        # Create dummy embeddings (1-hot like for simplicity without heavy models)
        d = len(self.arrhythmia_keys)
        self.index = faiss.IndexFlatL2(d)
        
        embeddings = np.eye(d).astype(np.float32)
        self.index.add(embeddings)
        
    def generate_explanation(self, arrhythmia_type, anomaly_score):
        try:
            query_idx = self.arrhythmia_keys.index(arrhythmia_type)
        except ValueError:
            return "Unknown Arrhythmia detected. Review ECG segment manually."
            
        # Create query vector
        query_vector = np.zeros((1, len(self.arrhythmia_keys)), dtype=np.float32)
        query_vector[0, query_idx] = 1.0
        
        # Search FAISS index
        D, I = self.index.search(query_vector, 1)
        retrieved_idx = I[0][0]
        
        base_explanation = self.explanations[retrieved_idx]
        
        if anomaly_score > 0.8:
            return f"{base_explanation} CRITICAL RISK: Anomaly score is very high ({anomaly_score:.2f})."
        return base_explanation

rag_generator = FAISSRAGGenerator()

