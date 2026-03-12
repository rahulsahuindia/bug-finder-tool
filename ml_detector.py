from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import os

class MLVulnDetector:
    def __init__(self, model_name="microsoft/codebert-base"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)  # binary: vulnerable or not
        self.model.eval()

    def predict(self, code_snippet):
        inputs = self.tokenizer(code_snippet, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = self.model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)
        vuln_prob = probs[0][1].item()  # probability of vulnerable
        return vuln_prob > 0.5  # threshold

    def scan_file(self, filepath):
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        # Split code into functions/methods for better prediction
        # Simplified: just scan whole file
        is_vuln = self.predict(code)
        if is_vuln:
            return [{"file": filepath, "type": "ML-predicted vulnerability", "confidence": "high"}]
        return []

