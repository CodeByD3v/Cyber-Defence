"""
Train Random Forest Models for Attack Detection

- Binary classification: Normal (0) vs Attack (1)
- Multiclass classification: Attack category prediction
Uses UNSW-NB15 dataset with 39 features.
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
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Features used for training (39 features)
FEATURE_COLS = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'dwin', 'tcprtt', 'synack',
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
        dataset_dir / "UNSW-NB15_3.csv",
        dataset_dir / "UNSW-NB15_4.csv",
    ]
    
    existing = [f for f in raw_files if f.exists()]
    if existing:
        print(f"Loading {len(existing)} raw files...")
        dfs = [pd.read_csv(f, header=None, low_memory=False) for f in existing]
        df = pd.concat(dfs, ignore_index=True)
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
        y = df['label'].fillna(0).astype(int)
    elif 'attack_cat' in df.columns:
        y = df['attack_cat'].apply(
            lambda x: 0 if pd.isna(x) or str(x).strip().lower() in ('', 'normal') else 1
        )
    else:
        raise ValueError("No label column found")
    return y


def create_multiclass_labels(df):
    """Create multiclass labels from attack_cat column."""
    if 'attack_cat' not in df.columns:
        raise ValueError("No attack_cat column found for multiclass")
    
    # Clean attack categories
    attack_cat = df['attack_cat'].fillna('Normal').astype(str).str.strip()
    attack_cat = attack_cat.replace('', 'Normal')
    
    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(attack_cat)
    
    return y, label_encoder


def preprocess_features(df):
    """Extract and preprocess features."""
    X = df[FEATURE_COLS].copy()
    
    for col in CATEGORICAL_COLS:
        X[col] = X[col].fillna('unknown').astype(str).str.strip().str.lower()
    
    for col in NUMERIC_COLS:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0.0)
    
    return X


def create_preprocessor():
    """Create sklearn preprocessor."""
    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
        ('scaler', StandardScaler())
    ])
    
    categorical_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value='unknown')),
        ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, NUMERIC_COLS),
            ('cat', categorical_transformer, CATEGORICAL_COLS)
        ]
    )
    
    return preprocessor


def ReportEncapsulator(y_test, y_pred, target_names=None):
    """Print classification report."""
    print("\n" + "="*60)
    print("CLASSIFICATION REPORT")
    print("="*60)
    
    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    if target_names:
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=target_names))
    else:
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    if len(cm) == 2:
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
    print("RANDOM FOREST MODELS TRAINING")
    print("="*60)
    
    # Load data
    print("\n[1/6] Loading dataset...")
    df = load_dataset()
    print(f"Loaded {len(df)} samples")
    
    # Prepare features
    print("\n[2/6] Preparing features...")
    X = preprocess_features(df)
    
    # Create preprocessor and fit/transform
    preprocessor = create_preprocessor()
    X_transformed = preprocessor.fit_transform(X)
    
    print(f"Features shape: {X_transformed.shape}")
    
    # ==================== BINARY CLASSIFICATION ====================
    print("\n" + "="*60)
    print("BINARY CLASSIFICATION (Normal vs Attack)")
    print("="*60)
    
    y_bin = create_binary_labels(df)
    print(f"Label distribution:")
    print(f"  Normal (0): {(y_bin == 0).sum()}")
    print(f"  Attack (1): {(y_bin == 1).sum()}")
    
    # Split data for binary
    X_train, X_test, y_train, y_test = train_test_split(
        X_transformed, y_bin, test_size=0.2, random_state=42, stratify=y_bin
    )
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    
    # Train binary model
    print("\n[3/6] Training Binary Random Forest...")
    rf_bin = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf_bin.fit(X_train, y_train)
    print("Binary model training complete!")
    
    # Evaluate binary
    y_pred = rf_bin.predict(X_test)
    ReportEncapsulator(y_test, y_pred, target_names=['Normal', 'Attack'])
    
    # ==================== MULTICLASS CLASSIFICATION ====================
    print("\n" + "="*60)
    print("MULTICLASS CLASSIFICATION (Attack Categories)")
    print("="*60)
    
    y_multi, label_encoder = create_multiclass_labels(df)
    print(f"Classes: {list(label_encoder.classes_)}")
    
    # Split data for multiclass
    Xa_train, Xa_test, ya_train, ya_test = train_test_split(
        X_transformed, y_multi, test_size=0.2, random_state=42, stratify=y_multi
    )
    print(f"Training samples: {len(Xa_train)}")
    print(f"Test samples: {len(Xa_test)}")
    
    # Train multiclass model
    print("\n[4/6] Training Multiclass Random Forest...")
    rf_multi = RandomForestClassifier(
        n_estimators=400,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf_multi.fit(Xa_train, ya_train)
    print("Multiclass model training complete!")
    
    # Evaluate multiclass
    y_pred = rf_multi.predict(Xa_test)
    ReportEncapsulator(ya_test, y_pred, target_names=list(label_encoder.classes_))
    
    # ==================== SAVE MODELS BUNDLE ====================
    print("\n[5/6] Saving models bundle...")
    model_path = Path("model/rf_models_bundle.joblib")
    model_path.parent.mkdir(exist_ok=True)
    
    model_data = {
        'preprocessor': preprocessor,
        'rf_binary': rf_bin,
        'rf_multiclass': rf_multi,
        'label_encoder': label_encoder,
        'classes_binary': ['Normal', 'Attack'],
        'classes_multiclass': list(label_encoder.classes_),
        'feature_cols': FEATURE_COLS,
        'model_type': 'binary',  # Default mode
        'algorithm': 'RandomForest'
    }
    
    joblib.dump(model_data, model_path)
    print(f"Models bundle saved to: {model_path}")
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
