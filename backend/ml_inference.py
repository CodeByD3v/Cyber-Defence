from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np


@dataclass(frozen=True)
class MlResult:
    malicious_score: float
    predicted_label: str  # attack type or 'Normal'
    model_mode: str  # 'binary' or 'multiclass'
    raw_class: Optional[str] = None


class ModelWrapper:
    def __init__(self, pipeline_path: Path):
        self._path = pipeline_path
        self._model_data = self._load_model(pipeline_path)
        
        # Handle both dict format (new) and direct pipeline (old)
        if isinstance(self._model_data, dict):
            self._pipe = self._model_data.get('pipeline')
            self._label_encoder = self._model_data.get('label_encoder')
            self._classes = self._model_data.get('classes', [])
            self._feature_cols = self._model_data.get('feature_cols', [])
        else:
            self._pipe = self._model_data
            self._label_encoder = None
            self._classes = []
            self._feature_cols = []
        
        # Fix sklearn version mismatch issues with imputer
        self._fix_imputer_dtype()

    def _fix_imputer_dtype(self):
        """Fix SimpleImputer dtype issues from sklearn version mismatch."""
        try:
            ct = self._pipe.named_steps.get('preprocessor')
            if ct:
                for name, trans, cols in ct.transformers_:
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

    def score_conn_features(self, features: Dict[str, Any]) -> MlResult:
        """Score features and return attack classification."""
        
        try:
            import pandas as pd
        except ModuleNotFoundError as e:
            raise ModuleNotFoundError("pandas required for inference") from e

        CATEGORICAL = {'proto', 'service', 'state'}

        try:
            # Build feature row with proper dtype handling
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
            
            # Get prediction
            pred_encoded = self._pipe.predict(X)[0]
            
            # Get probabilities if available
            proba = None
            confidence = 0.5
            if hasattr(self._pipe, "predict_proba"):
                proba = self._pipe.predict_proba(X)[0]
                confidence = float(np.max(proba))
            
            # Decode label
            if self._label_encoder is not None:
                pred_label = self._label_encoder.inverse_transform([pred_encoded])[0]
            elif self._classes:
                pred_label = self._classes[pred_encoded] if pred_encoded < len(self._classes) else str(pred_encoded)
            else:
                pred_label = str(pred_encoded)
            
            # Determine if malicious
            is_normal = str(pred_label).lower() in {'normal', 'benign', '0'}
            
            return MlResult(
                malicious_score=confidence if not is_normal else 1.0 - confidence,
                predicted_label=str(pred_label),
                model_mode="multiclass" if len(self._classes) > 2 else "binary",
                raw_class=str(pred_label)
            )
        
        except Exception as e:
            import traceback
            traceback.print_exc()
            return MlResult(
                malicious_score=0.5,
                predicted_label="Error",
                model_mode="error",
                raw_class=str(e)
            )
