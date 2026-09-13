import numpy as np
import joblib
import xgboost as xgb
from sklearn.model_selection import train_test_split

print("[*] Generating synthetic network dataset...")
np.random.seed(42)

# Features: [packets_per_sec, unique_dst_ips, avg_packet_len]
# Class 0: Normal Traffic (Low pps, low unique IPs, mid packet size)
normal = np.random.multivariate_normal(
    [5, 2, 500], [[2, 0.5, 0], [0.5, 0.5, 0], [0, 0, 5000]], 10000
)
labels_normal = np.zeros(10000)

# Class 1: DDoS Attack (Massive pps, low unique IPs, large packet size)
ddos = np.random.multivariate_normal(
    [2500, 1, 1400], [[10000, 0, 0], [0, 0, 0], [0, 0, 1000]], 500
)
labels_ddos = np.ones(500)

# Class 2: Port Scan (High pps, massive unique IPs, low packet size)
port_scan = np.random.multivariate_normal(
    [300, 80, 64], [[2500, 0, 0], [0, 100, 0], [0, 0, 0]], 500
)
labels_scan = np.ones(500) * 2

# Combine into training arrays
X = np.vstack([normal, ddos, port_scan])
y = np.concatenate([labels_normal, labels_ddos, labels_scan])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("[*] Training Tier 2 XGBoost Classifier...")
model = xgb.XGBClassifier(eval_metric="mlogloss", random_state=42)
model.fit(X_train, y_train)

# Save to disk
joblib.dump(model, "xgboost_ids.pkl")
print("[*] Model saved successfully as 'xgboost_ids.pkl'!")
