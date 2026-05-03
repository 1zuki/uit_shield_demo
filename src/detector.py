from __future__ import annotations

from pathlib import Path
from typing import Any
import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from .features import rule_based_risk, stop_recommendation

LABELS = ["safe", "spam", "phishing"]
HIGH_RISK_THRESHOLD = 0.60
MEDIUM_RISK_THRESHOLD = 0.45

def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, strip_accents=None, ngram_range=(1, 2), min_df=1, max_features=12000)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])

def load_dataset(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)

    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain columns: text,label")

    df = df[["text", "label"]].dropna()
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(str).str.lower().str.strip()
    invalid = sorted(set(df["label"]) - set(LABELS))

    if invalid:
        raise ValueError(f"Invalid labels: {invalid}. Allowed labels: {LABELS}")

    return df

def train_model(data_path: str | Path, model_path: str | Path, test_size: float = 0.25) -> dict[str, Any]:
    df = load_dataset(data_path)
    stratify = df["label"] if df["label"].value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(df["text"], df["label"], test_size=test_size, random_state=42, stratify=stratify)

    model = build_pipeline()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, zero_division=0, output_dict=True)

    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    return {"model_path": str(model_path), "num_rows": int(len(df)), "labels": sorted(df["label"].unique().tolist()), "report": report}

def load_model(model_path: str | Path):
    return joblib.load(model_path)

def ml_predict(model, text: str) -> dict[str, Any]:
    text = text or ""
    prediction = model.predict([text])[0]
    probabilities = {}

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba([text])[0]
        probabilities = {str(label): float(prob) for label, prob in zip(model.classes_, probs)}
    else:
        probabilities = {prediction: 1.0}

    phishing_like_prob = max(probabilities.get("phishing", 0.0), 0.65 * probabilities.get("spam", 0.0))

    return {"prediction": str(prediction), "probabilities": probabilities, "phishing_like_prob": float(phishing_like_prob)}

def combined_analyze(model, text: str) -> dict[str, Any]:
    ml = ml_predict(model, text)
    rule_score, details = rule_based_risk(text)
    combined_score = max(0.0, min(1.0, (0.65 * ml["phishing_like_prob"]) + (0.35 * rule_score)))
    severe_rule_ml_consensus = rule_score >= 0.75 and ml["prediction"] == "phishing"

    if combined_score >= HIGH_RISK_THRESHOLD or severe_rule_ml_consensus:
        risk_label = "phishing"; display_label = "High risk / Phishing"
    elif combined_score >= MEDIUM_RISK_THRESHOLD:
        risk_label = "spam"; display_label = "Medium risk / Suspicious"
    else:
        risk_label = "safe"; display_label = "Low risk / Probably safe"

    return {"display_label": display_label, "risk_label": risk_label, "combined_score": float(combined_score), "ml": ml, "rule_score": float(rule_score), "details": details, "stop_recommendation": stop_recommendation(risk_label)}
