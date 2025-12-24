from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np


@dataclass(frozen=True)
class MlResult:
    malicious_score: float
    predicted_label: str  # 'Attack' or 'Normal' for binary, attack type for multiclass
    model_mode: str  # 'binary' or 'multiclass'
    raw_class: Optional[str] = None


class ModelWrapper:
    def __init__(self, pipeline_path: Path):
        self._path = pipeline_path
        self._model_data = self._load_model(pipeline_path)
        
        # Handle bundle format (new) vs pipeline format (old)
        if isinstance(self._model_data, dict):
            # New bundle format with separate preprocessor and models
            self._preprocessor = self._model_data.get('preprocessor')
            self._rf_binary = self._model_data.get('rf_binary')
            self._rf_multiclass = self._model_data.get('rf_multiclass')
            self._pipe = self._model_data.get('pipeline')  # Fallback for old format
            self._label_encoder = self._model_data.get('label_encoder')
            self._classes_binary = self._model_data.get('classes_binary', ['Normal', 'Attack'])
            self._classes_multiclass = self._model_data.get('classes_multiclass', [])
            self._feature_cols = self._model_data.get('feature_cols', [])
            self._model_type = self._model_data.get('model_type', 'binary')
            self._algorithm = self._model_data.get('algorithm', 'RandomForest')
        else:
            # Direct pipeline (legacy)
            self._preprocessor = None
            self._rf_binary = None
            self._rf_multiclass = None
            self._pipe = self._model_data
            self._label_encoder = None
            self._classes_binary = ['Normal', 'Attack']
            self._classes_multiclass = []
            self._feature_cols = []
            self._model_type = 'multiclass'
            self._algorithm = 'XGBoost'
        
        # Fix sklearn version mismatch issues
        self._fix_imputer_dtype()
        
        print(f"[ML] Loaded {self._algorithm} model ({self._model_type} classification)")

    def _fix_imputer_dtype(self):
        """Fix SimpleImputer dtype issues from sklearn version mismatch."""
        try:
            preprocessor = self._preprocessor or (self._pipe.named_steps.get('preprocessor') if self._pipe else None)
            if preprocessor:
                for name, trans, cols in preprocessor.transformers_:
                    if hasattr(trans, 'named_steps'):
                        imputer = trans.named_steps.get('imputer')
                        if imputer and hasattr(imputer, 'statistics_'):
                            if imputer.statistics_ is not None:
                                if imputer.statistics_.dtype == object:
                                    try:
                                        imputer.statistics_ = imputer.statistics_.astype(np.float64)
                                    except:
                                        pass
        except Exception:
            pass

    @staticmethod
    def _load_model(path: Path) -> Any:
        try:
            import joblib
            return joblib.load(path)
        except Exception:
            import pickle
            with path.open("rb") as f:
                return pickle.load(f)


    def _prepare_features(self, features: Dict[str, Any]):
        """Prepare features for prediction."""
        import pandas as pd
        
        CATEGORICAL = {'proto', 'service', 'state'}
        
        if self._feature_cols:
            row = {}
            for col in self._feature_cols:
                if col in features:
                    val = features[col]
                elif col in CATEGORICAL:
                    val = 'unknown'
                else:
                    val = 0.0
                
                # Ensure proper dtype
                if col in CATEGORICAL:
                    if val is None or (isinstance(val, str) and not val.strip()):
                        val = 'unknown'
                    row[col] = str(val).strip().lower()
                else:
                    # Convert to float for numeric columns
                    if val is None or val == '' or (isinstance(val, str) and val.strip() in ('', '-', 'nan')):
                        row[col] = 0.0
                    elif isinstance(val, str):
                        try:
                            row[col] = float(val.strip()) if val.strip() else 0.0
                        except ValueError:
                            row[col] = 0.0
                    else:
                        try:
                            row[col] = float(val) if not (isinstance(val, float) and np.isnan(val)) else 0.0
                        except (ValueError, TypeError):
                            row[col] = 0.0
                
            X = pd.DataFrame([row])
        else:
            X = pd.DataFrame([features])
        
        # Ensure categorical columns are strings
        for col in CATEGORICAL:
            if col in X.columns:
                X[col] = X[col].fillna('unknown').astype(str).str.strip().str.lower()
        
        # Ensure numeric columns are float and fill NaN
        for col in X.columns:
            if col not in CATEGORICAL:
                X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0.0)
        
        return X

    def score_conn_features(self, features: Dict[str, Any]) -> MlResult:
        """Score features and return attack classification."""
        
        try:
            import pandas as pd
        except ModuleNotFoundError as e:
            raise ModuleNotFoundError("pandas required for inference") from e

        try:
            X = self._prepare_features(features)
            
            # New bundle format: preprocessor + separate models
            if self._preprocessor is not None and self._rf_binary is not None:
                X_transformed = self._preprocessor.transform(X)
                
                # Binary prediction
                pred_encoded = self._rf_binary.predict(X_transformed)[0]
                proba = self._rf_binary.predict_proba(X_transformed)[0] if hasattr(self._rf_binary, 'predict_proba') else None
                
                is_attack = int(pred_encoded) == 1
                pred_label = 'Attack' if is_attack else 'Normal'
                
                if proba is not None and len(proba) >= 2:
                    malicious_score = float(proba[1])
                else:
                    malicious_score = 1.0 if is_attack else 0.0
                
                # If attack detected and multiclass model available, get attack type
                attack_type = None
                if is_attack and self._rf_multiclass is not None:
                    try:
                        multi_pred = self._rf_multiclass.predict(X_transformed)[0]
                        if self._label_encoder is not None:
                            attack_type = self._label_encoder.inverse_transform([multi_pred])[0]
                        elif self._classes_multiclass:
                            attack_type = self._classes_multiclass[multi_pred] if multi_pred < len(self._classes_multiclass) else str(multi_pred)
                    except Exception:
                        pass
                
                return MlResult(
                    malicious_score=malicious_score,
                    predicted_label=attack_type if attack_type and attack_type.lower() != 'normal' else pred_label,
                    model_mode="binary",
                    raw_class=attack_type or str(pred_encoded)
                )
            
            # Legacy pipeline format
            if self._pipe is not None:
                pred_encoded = self._pipe.predict(X)[0]
                proba = None
                confidence = 0.5
                
                if hasattr(self._pipe, "predict_proba"):
                    proba = self._pipe.predict_proba(X)[0]
                    confidence = float(np.max(proba))
                
                if self._model_type == 'binary':
                    is_attack = int(pred_encoded) == 1
                    pred_label = 'Attack' if is_attack else 'Normal'
                    
                    if proba is not None and len(proba) >= 2:
                        malicious_score = float(proba[1])
                    else:
                        malicious_score = confidence if is_attack else 1.0 - confidence
                    
                    return MlResult(
                        malicious_score=malicious_score,
                        predicted_label=pred_label,
                        model_mode="binary",
                        raw_class=str(pred_encoded)
                    )
                
                # Multiclass
                if self._label_encoder is not None:
                    pred_label = self._label_encoder.inverse_transform([pred_encoded])[0]
                elif self._classes_multiclass:
                    pred_label = self._classes_multiclass[pred_encoded] if pred_encoded < len(self._classes_multiclass) else str(pred_encoded)
                else:
                    pred_label = str(pred_encoded)
                
                is_normal = str(pred_label).lower() in {'normal', 'benign', '0'}
                
                return MlResult(
                    malicious_score=confidence if not is_normal else 1.0 - confidence,
                    predicted_label=str(pred_label),
                    model_mode="multiclass",
                    raw_class=str(pred_label)
                )
            
            raise ValueError("No valid model found in bundle")
        
        except Exception as e:
            import traceback
            traceback.print_exc()
            return MlResult(
                malicious_score=0.5,
                predicted_label="Error",
                model_mode="error",
                raw_class=str(e)
            )
