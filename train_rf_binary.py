"""
Train Random Forest Binary Classifier for Attack Detection

Binary classification: Normal (0) vs Attack (1)
Uses UNSW-NB15 dataset with 41 features.
"""

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Features used for training (41 features - no data leakage)
FEATURE_COLS = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'dwin', 'stcpb', 'dtcpb', 'tcprtt', 'synack',
    'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len',
    'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
    'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd',
    'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

CATEGORICAL_COLS = ['proto', 'service', 'state']
NUMERIC_COLS = [c for c in FEATURE_COLS if c not in CATEGORICAL_COLS]


def load_dataset():
    """Load UNSW-NB15 dataset."""
    dataset_dir = Path("Dataset")
    
    # Try training set first
    train_file = dataset_dir / "UNSW_NB15_training-set.csv"
    if train_file.exists():
        print(f"Loading {train_file}...")
        df = pd.read_csv(train_file, low_memory=False)
        return df
    
    # Try raw files
    raw_files = [
        dataset_dir / "UNSW-NB15_1.csv",
        dataset_dir / "UNSW-NB15_2.csv",
    ]
    
    existing = [f for f in raw_files if f.exists()]
    if existing:
        print(f"Loading {len(existing)} raw files...")
        dfs = [pd.read_csv(f, header=None, low_memory=False) for f in existing]
        df = pd.concat(dfs, ignore_index=True)
        # Set column names for raw files
        RAW_COLUMNS = [
            'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur',
            'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service',
            'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
            'smean', 'dmean', 'trans_depth', 'response_body_len', 'sjit', 'djit',
            'stime', 'ltime', 'sinpkt', 'dinpkt', 'tcprtt', 'synack', 'ackdat',
            'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login',
            'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
            'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
        ]
        df.columns = RAW_COLUMNS
        return df
    
    raise FileNotFoundError("No dataset files found in Dataset/ folder")


def create_binary_labels(df):
    """Create binary labels: 0 = Normal, 1 = Attack."""
    if 'label' in df.columns:
        # label column: 0 = normal, 1 = attack
        y = df['label'].fillna(0).astype(int)
    elif 'attack_cat' in df.columns:
        # attack_cat column: empty/Normal = 0, others = 1
        y = df['attack_cat'].apply(
            lambda x: 0 if pd.isna(x) or str(x).strip().lower() in ('', 'normal') else 1
        )
    else:
        raise ValueError("No label column found")
    
    return y


def preprocess_features(df):
    """Extract and preprocess features."""
    X = df[FEATURE_COLS].copy()
    
    # Handle categorical columns
    for col in CATEGORICAL_COLS:
        X[col] = X[col].fillna('unknown').astype(str).str.strip().str.lower()
    
    # Handle numeric columns
    for col in NUMERIC_COLS:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0.0)
    
    return X


def create_pipeline():
    """Create sklearn pipeline with preprocessing."""
    from sklearn.preprocessing import OneHotEncoder
    
    # Numeric preprocessing
    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
        ('scaler', StandardScaler())
    ])
    
    # Categorical preprocessing
    categorical_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value='unknown')),
        ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])
    
    # Column transformer
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, NUMERIC_COLS),
            ('cat', categorical_transformer, CATEGORICAL_COLS)
        ]
    )
    
    # Full pipeline with Random Forest
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(
            n_estimators=300,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2
        ))
    ])
    
    return pipeline


def report_results(y_test, y_pred, y_proba=None):
    """Print classification report."""
    print("\n" + "="*60)
    print("CLASSIFICATION REPORT")
    print("="*60)
    
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                Predicted")
    print(f"              Normal  Attack")
    print(f"Actual Normal  {cm[0,0]:6d}  {cm[0,1]:6d}")
    print(f"Actual Attack  {cm[1,0]:6d}  {cm[1,1]:6d}")
    
    # Calculate additional metrics
    tn, fp, fn, tp = cm.ravel()
    print(f"\nTrue Negatives:  {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"True Positives:  {tp}")
    print(f"\nPrecision (Attack): {tp/(tp+fp):.4f}")
    print(f"Recall (Attack):    {tp/(tp+fn):.4f}")
    print(f"F1-Score (Attack):  {2*tp/(2*tp+fp+fn):.4f}")


def main():
    print("="*60)
    print("RANDOM FOREST BINARY CLASSIFIER TRAINING")
    print("="*60)
    
    # Load data
    print("\n[1/5] Loading dataset...")
    df = load_dataset()
    print(f"Loaded {len(df)} samples")
    
    # Prepare features and labels
    print("\n[2/5] Preparing features...")
    X = preprocess_features(df)
    y = create_binary_labels(df)
    
    print(f"Features shape: {X.shape}")
    print(f"Label distribution:")
    print(f"  Normal (0): {(y == 0).sum()}")
    print(f"  Attack (1): {(y == 1).sum()}")
    
    # Split data
    print("\n[3/5] Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    
    # Train model
    print("\n[4/5] Training Random Forest...")
    pipeline = create_pipeline()
    pipeline.fit(X_train, y_train)
    print("Training complete!")
    
    # Evaluate
    print("\n[5/5] Evaluating model...")
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)
    
    report_results(y_test, y_pred, y_proba)
    
    # Save model
    model_path = Path("model/rf_binary_classifier.joblib")
    model_path.parent.mkdir(exist_ok=True)
    
    model_data = {
        'pipeline': pipeline,
        'label_encoder': None,
        'classes': ['Normal', 'Attack'],
        'feature_cols': FEATURE_COLS,
        'model_type': 'binary',
        'algorithm': 'RandomForest'
    }
    
    joblib.dump(model_data, model_path)
    print(f"\nModel saved to: {model_path}")
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
