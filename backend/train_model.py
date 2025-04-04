# train_model.py

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import pickle

# Dummy dataset generation
# Features: [open_ports, num_services, cvss_score, device_type]
data = []
labels = []

for _ in range(500):
    open_ports = np.random.randint(1, 20)
    num_services = np.random.randint(1, 10)
    cvss_score = np.round(np.random.uniform(0, 10), 1)
    device_type = np.random.randint(0, 3)  # 0 = router, 1 = camera, 2 = printer, etc.

    # Dummy labeling logic
    if cvss_score > 7 and open_ports > 10:
        risk_level = 2  # High
    elif cvss_score > 4:
        risk_level = 1  # Medium
    else:
        risk_level = 0  # Low

    data.append([open_ports, num_services, cvss_score, device_type])
    labels.append(risk_level)

# Train DataFrame
df = pd.DataFrame(data, columns=['open_ports', 'num_services', 'cvss_score', 'device_type'])
labels = np.array(labels)

# Train Random Forest
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(df, labels)

# Save model
with open('rf_model.pkl', 'wb') as f:
    pickle.dump(rf, f)

print("[+] Model trained and saved as rf_model.pkl!")
