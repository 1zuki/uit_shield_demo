from __future__ import annotations

from pathlib import Path
import pandas as pd
import streamlit as st

from src.detector import combined_analyze, load_model, train_model

APP_TITLE = "UIT Shield Demo — Email Phishing Risk Detector"
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "uit_shield_model.joblib"
DATA_PATH = BASE_DIR / "data" / "sample_emails.csv"

st.set_page_config(page_title="UIT Shield Demo", page_icon="🛡️", layout="wide")

@st.cache_resource
def get_model():
    if not MODEL_PATH.exists():
        train_model(DATA_PATH, MODEL_PATH)

    return load_model(MODEL_PATH)

def score_badge(risk_label: str) -> str:
    if risk_label == "phishing": return "🔴 High Risk"
    if risk_label == "spam": return "🟠 Medium Risk"
    return "🟢 Low Risk"

def render_analysis(result: dict):
    score = result["combined_score"]
    risk_label = result["risk_label"]

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk level", score_badge(risk_label))
    col2.metric("Combined risk score", f"{score:.0%}")
    col3.metric("Rule-based score", f"{result['rule_score']:.0%}")

    st.subheader("Prediction")
    st.write(f"**Result:** {result['display_label']}")

    with st.expander("ML probabilities"):
        st.json({k: round(v, 4) for k, v in result["ml"]["probabilities"].items()})

    st.subheader("Why was it flagged?")
    details = result["details"]
    triggers = details.get("triggers", [])
    urls = details.get("urls", [])

    if not triggers and not urls:
        st.success("No obvious psychological triggers or suspicious URLs were detected.")

    if triggers:
        st.write("**Psychological manipulation triggers:**")

        for item in triggers:
            st.write(f"- `{item['category']}`: {', '.join(item['matches'])}")

    if urls:
        st.write("**URL analysis:**")

        for item in urls:
            st.write(f"- URL: `{item['url']}`")
            st.write(f"  - Domain: `{item['domain']}`")
            st.write(f"  - URL risk: `{item['risk']:.0%}`")

            if item["reasons"]:
                for reason in item["reasons"]:
                    st.write(f"  - Reason: {reason}")
            else:
                st.write("  - No obvious URL issue detected.")

    st.subheader("Suggested S.T.O.P response")

    for rec in result["stop_recommendation"]:
        st.write(f"- {rec}")

def main():
    st.title(APP_TITLE)
    st.caption("Demo version")
    model = get_model()

    sample_phishing = """[Phòng Đào tạo UIT] KHẨN CẤP: Tài khoản sinh viên của bạn sẽ bị khóa trong 24 giờ.\nVui lòng xác minh ngay tại: http://uit-edu-vn-login.verify-account.com\nNếu không hoàn tất, bạn có thể bị hủy đăng ký học phần."""

    sample_safe = """Phòng Công tác Sinh viên thông báo lịch sinh hoạt công dân đầu khóa.\nSinh viên xem chi tiết trên cổng thông tin chính thức của trường hoặc liên hệ lớp trưởng nếu cần hỗ trợ."""

    tab1, tab2, tab3 = st.tabs(["Analyze one message", "Batch CSV demo", "About"])

    with tab1:
        st.subheader("Paste email/message content")
        example = st.radio("Quick examples", ["Blank", "Phishing-like example", "Safe example"], horizontal=True)
        default_text = sample_phishing if example == "Phishing-like example" else sample_safe if example == "Safe example" else ""
        text = st.text_area("Email/message text", value=default_text, height=260, placeholder="Paste the full email or message here...")

        if st.button("Analyze", type="primary"):
            if not text.strip(): st.warning("Please paste an email/message first.")
            else: render_analysis(combined_analyze(model, text))

    with tab2:
        st.subheader("Batch analysis")
        st.write("Upload a CSV file with a column named `text`.")
        uploaded = st.file_uploader("Upload CSV", type=["csv"])

        if uploaded is not None:
            df = pd.read_csv(uploaded)

            if "text" not in df.columns:
                st.error("CSV must contain a `text` column.")
            else:
                rows = []

                for value in df["text"].fillna("").astype(str):
                    result = combined_analyze(model, value)
                    rows.append({"text": value[:120] + ("..." if len(value) > 120 else ""), "prediction": result["display_label"], "risk_score": round(result["combined_score"], 4), "rule_score": round(result["rule_score"], 4)})
                st.dataframe(pd.DataFrame(rows), use_container_width=True)

    with tab3:
        st.subheader("What this prototype does")
        st.write("This demo combines a machine learning text classifier with rule-based checks for urgency, fear, authority pressure, reward bait, credential requests, and suspicious URLs.")
        st.write("The goal is not to replace judgment. The goal is to make the user pause, observe suspicious signs, and apply S.T.O.P before clicking.")
        st.code("User pastes email → Model + rules analyze → Risk score → Reasons → S.T.O.P suggestion", language="text")

if __name__ == "__main__":
    main()
