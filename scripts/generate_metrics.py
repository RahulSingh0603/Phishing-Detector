import os
import sys
import time
import json
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
    classification_report
)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_FILE = os.path.join(BASE_DIR, 'dataset', 'urls.csv')
MODEL_FILE = os.path.join(BASE_DIR, 'backend', 'ml', 'model.pkl')
OUTPUT_DIR = os.path.join(BASE_DIR, 'dashboard', 'reports')
os.makedirs(OUTPUT_DIR, exist_ok=True)

sys.path.append(BASE_DIR)
from backend.ml.features import extract_features, get_feature_names

def generate_report():
    print("=" * 60)
    print("Generating Academic Evaluation Metrics & High-Res Graphs...")
    print("=" * 60)

    # 1. Load Model & Dataset
    model = joblib.load(MODEL_FILE)
    df = pd.read_csv(DATASET_FILE)
    
    feature_names = get_feature_names()
    print("Extracting features for evaluation...")
    features_list = df['url'].apply(extract_features).tolist()
    X = pd.DataFrame(features_list)[feature_names]
    y = df['label'].astype(int)

    # Split (Same test distribution as training)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]

    # Style configuration
    plt.style.use('dark_background')
    palette_primary = '#38bdf8'
    palette_danger = '#f43f5e'

    # --- 1. Confusion Matrix ---
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 5), dpi=300)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                xticklabels=['Legitimate (0)', 'Phishing (1)'],
                yticklabels=['Legitimate (0)', 'Phishing (1)'])
    plt.title('Confusion Matrix - PhishGuard AI', fontsize=14, pad=15, color='white', weight='bold')
    plt.ylabel('Actual Truth', fontsize=11, color='#94a3b8')
    plt.xlabel('Predicted Label', fontsize=11, color='#94a3b8')
    plt.tight_layout()
    cm_path = os.path.join(OUTPUT_DIR, 'confusion_matrix.png')
    plt.savefig(cm_path)
    plt.close()
    print(f"Saved: {cm_path}")

    # --- 2. ROC-AUC Curve ---
    fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(6, 5), dpi=300)
    plt.plot(fpr, tpr, color=palette_primary, lw=2.5, label=f'XGBoost (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='#64748b', lw=1.5, linestyle='--', label='Random Guess')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate (FPR)', fontsize=11, color='#94a3b8')
    plt.ylabel('True Positive Rate (TPR / Recall)', fontsize=11, color='#94a3b8')
    plt.title('Receiver Operating Characteristic (ROC)', fontsize=14, pad=15, color='white', weight='bold')
    plt.legend(loc="lower right", frameon=True, facecolor='#1e293b')
    plt.grid(alpha=0.2)
    plt.tight_layout()
    roc_path = os.path.join(OUTPUT_DIR, 'roc_curve.png')
    plt.savefig(roc_path)
    plt.close()
    print(f"Saved: {roc_path}")

    # --- 3. Latency / Response Time Benchmark ---
    print("\nBenchmarking Model & Feature Extraction Latency...")
    sample_urls = df['url'].sample(n=300, random_state=42).tolist()
    latencies = []
    
    # Warmup
    for _ in range(5):
        extract_features("https://warmup.example.com")

    for u in sample_urls:
        t0 = time.perf_counter()
        f = extract_features(u)
        feat_df = pd.DataFrame([f])[feature_names]
        _ = model.predict_proba(feat_df)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed_ms)

    avg_latency = float(np.mean(latencies))
    p95_latency = float(np.percentile(latencies, 95))
    p99_latency = float(np.percentile(latencies, 99))
    print(f"Average Latency: {avg_latency:.2f} ms | p95: {p95_latency:.2f} ms | p99: {p99_latency:.2f} ms")

    plt.figure(figsize=(6, 5), dpi=300)
    sns.histplot(latencies, bins=30, kde=True, color='#10b981', edgecolor='black')
    plt.axvline(avg_latency, color='#f59e0b', linestyle='--', lw=2, label=f'Mean: {avg_latency:.2f} ms')
    plt.axvline(p95_latency, color=palette_danger, linestyle=':', lw=2, label=f'95th %: {p95_latency:.2f} ms')
    plt.title('Prediction Latency Distribution (ms)', fontsize=14, pad=15, color='white', weight='bold')
    plt.xlabel('Inference Latency (Milliseconds)', fontsize=11, color='#94a3b8')
    plt.ylabel('Frequency', fontsize=11, color='#94a3b8')
    plt.legend(loc="upper right", frameon=True, facecolor='#1e293b')
    plt.grid(alpha=0.2)
    plt.tight_layout()
    latency_path = os.path.join(OUTPUT_DIR, 'latency_distribution.png')
    plt.savefig(latency_path)
    plt.close()
    print(f"Saved: {latency_path}")

    # Summary metrics JSON for Dashboard
    metrics = {
        "accuracy": float(np.mean(y_pred == y_test)),
        "roc_auc": float(roc_auc),
        "mean_latency_ms": round(avg_latency, 2),
        "p95_latency_ms": round(p95_latency, 2),
        "true_positives": int(cm[1][1]),
        "true_negatives": int(cm[0][0]),
        "false_positives": int(cm[0][1]),
        "false_negatives": int(cm[1][0]),
        "total_test_samples": len(y_test)
    }

    with open(os.path.join(OUTPUT_DIR, 'metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=4)

    print("\nAll academic metrics and charts generated successfully!")

if __name__ == '__main__':
    generate_report()
