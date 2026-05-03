# UIT Shield Demo — Email Phishing Risk Detector

Prototype for presenting **UIT Shield** approach in my SS004 class: the user manually pastes an email/message, and the system predicts whether it is **safe**, **spam**, or **phishing**, then explains the suspicious signs.

Scope:
- No Gmail login or OAuth.
- No private inbox scanning.
- No image/video/document OCR.
- Manual paste-in email/message analysis only.
- Simple ML + rule-based psychological trigger detection.

## Features

- Prediction: Safe / Spam / Phishing
- Risk score and ML confidence
- Suspicious URLs
- Psychological manipulation keywords
- Suggested S.T.O.P response
- Batch CSV analysis for demo/testing

## Project structure

```text
uit_shield_demo/
├── app.py
├── train_model.py
├── requirements.txt
├── README.md
├── demo_cases.md
├── data/sample_emails.csv
├── models/uit_shield_model.joblib
└── src/
    ├── __init__.py
    ├── features.py
    └── detector.py
```

## Setup

```bash
cd uit_shield_demo
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

## Train

```bash
python train_model.py
```

## Run app

```bash
streamlit run app.py
```

## Train with your own CSV

CSV format:

```csv
text,label
"Your email content here",phishing
"Normal school announcement",safe
"Buy now discount",spam
```

Allowed labels: `safe`, `spam`, `phishing`.

```bash
python train_model.py --data data/your_dataset.csv
```

## Presentation script

> Đây là bản mô phỏng đơn giản của UIT Shield. Công cụ chưa tích hợp trực tiếp Gmail mà hoạt động theo cách người dùng dán nội dung email hoặc tin nhắn vào hệ thống. Mục tiêu không phải thay thế hoàn toàn khả năng phán đoán của sinh viên, mà hỗ trợ sinh viên nhận diện các dấu hiệu nguy hiểm, đặc biệt là các yếu tố thao túng tâm lý như tính cấp bách, đe dọa, hứa hẹn lợi ích hoặc yêu cầu xác minh tài khoản.

## Note

The included dataset is intentionally small for demo purposes. For real deployment, use a larger labeled dataset and evaluate carefully.
