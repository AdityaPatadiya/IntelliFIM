import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
from .log_parser import parse_log_file

MODEL_DIR = os.path.join("data", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "anomaly_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

def train_anomaly_model():
    log_folder_path = 'logs'
    log_dfs = []
    for file in os.listdir(log_folder_path):
        file_path = os.path.join(log_folder_path, file)
        log_df = parse_log_file(file_path)
        if log_df is not None and not log_df.empty:
            log_dfs.append(log_df)

    if not log_dfs:
        print("No log data available for training.")
        return None, None

    log_df = pd.concat(log_dfs, ignore_index=True)

    # Convert log messages to TF-IDF features
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(log_df['message'])

    # Train Isolation Forest model
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)

    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save the trained model & vectorizer
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print("Anomaly detection model trained and saved.")

    return vectorizer, model

def load_vectorizer_model():
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        print("Loaded saved model and vectorizer.")
    else:
        print("No pre-trained model found. Training a new model...")
        vectorizer, model = train_anomaly_model()

    return vectorizer, model

if __name__ == "__main__":
    train_anomaly_model()
