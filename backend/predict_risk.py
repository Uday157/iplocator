import os
import pickle
import numpy as np
import pandas as pd  # Needed to format the input correctly

# Dynamically locate the model file relative to this script's location
MODEL_PATH = os.path.join(os.path.dirname(__file__), "rf_model.pkl")

# Load the trained model
with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

# Define correct feature names (matching what was used during training)
FEATURE_COLUMNS = ["open_ports", "num_services", "cvss_score", "device_type"]

def predict_risk(open_ports, services, cvss_score, device_type):
    # Rename 'services' to 'num_services' to match the trained model
    input_data = pd.DataFrame([[open_ports, services, cvss_score, device_type]], columns=FEATURE_COLUMNS)
    
    # Make prediction
    prediction = model.predict(input_data)[0]
    
    risk_map = {0: "Low", 1: "Medium", 2: "High"}
    return risk_map.get(prediction, "Unknown")

# Example usage:
if __name__ == "__main__":
    risk = predict_risk(3, 2, 8.8, 1)  # Test with dummy values
    print(f"[+] Predicted Risk Level: {risk}")
