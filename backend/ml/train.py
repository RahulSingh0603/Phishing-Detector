import os
import sys
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Add the root directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend.ml.features import extract_features, get_feature_names

def train_model(dataset_path: str, model_path: str):
    print(f"Loading dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"Error: Dataset not found at {dataset_path}.")
        return

    # Clean missing values and normalize
    df = df.dropna(subset=['url', 'label'])
    print(f"Total dataset records: {len(df)}")
    print("Class distribution:")
    print(df['label'].value_counts())

    print("\nExtracting features from URLs... (vectorized feature extraction)")
    feature_names = get_feature_names()
    
    # Apply feature extraction
    features_list = df['url'].apply(extract_features).tolist()
    X = pd.DataFrame(features_list)[feature_names] # Ensure consistent order
    y = df['label'].astype(int)

    print("Splitting data into train/test sets (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training XGBoost model on real-world phishing data...")
    model = XGBClassifier(
        n_estimators=150, 
        max_depth=6, 
        learning_rate=0.08, 
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='logloss'
    )
    model.fit(X_train, y_train)

    print("\nEvaluating model on held-out test data...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]))

    print(f"Saving retrained model to {model_path}...")
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print("Model training and saving complete successfully!")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    dataset_file = os.path.join(base_dir, 'dataset', 'urls.csv')
    model_file = os.path.join(base_dir, 'backend', 'ml', 'model.pkl')
    
    train_model(dataset_file, model_file)
