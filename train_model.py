from __future__ import annotations
import argparse, json
from pathlib import Path
from src.detector import train_model

BASE_DIR = Path(__file__).resolve().parent

def main() -> None:
    parser = argparse.ArgumentParser(description="Train UIT Shield phishing/spam detector.")
    parser.add_argument("--data", default=str(BASE_DIR / "data" / "sample_emails.csv"), help="CSV path with text,label columns.")
    parser.add_argument("--model", default=str(BASE_DIR / "models" / "uit_shield_model.joblib"), help="Output model path.")
    parser.add_argument("--report", default=str(BASE_DIR / "models" / "training_report.json"), help="Output report path.")

    args = parser.parse_args()

    result = train_model(args.data, args.model)
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Model saved to: {result['model_path']}")
    print(f"Training rows: {result['num_rows']}")
    print(f"Labels: {', '.join(result['labels'])}")
    print(f"Report saved to: {report_path}")

if __name__ == "__main__":
    main()
