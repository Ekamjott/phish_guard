
from flask import send_file
from reportlab.pdfgen import canvas
import io
from flask import Flask, render_template, request
import sqlite3
import re
import validators

app = Flask(__name__)

# -------------------------------
# Create Database
# -------------------------------

def create_database():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        subject TEXT,
        score INTEGER,
        risk TEXT
    )
    """)

    conn.commit()
    conn.close()

create_database()

# -------------------------------
# Phishing Detection Function
# -------------------------------

def analyze_email(sender, subject, body):

    score = 0
    reasons = []

    keywords = [
        "verify",
        "login",
        "password",
        "urgent",
        "bank",
        "account",
        "click here",
        "limited time",
        "winner",
        "free",
        "confirm",
        "otp",
        "refund",
        "invoice"
    ]

    text = (subject + " " + body).lower()

    # Keyword Detection
    for word in keywords:
        if word in text:
            score += 8
            reasons.append(f"Suspicious keyword: {word}")

    # HTTP Link
    if "http://" in body:
        score += 20
        reasons.append("Uses insecure HTTP link")

    # URL Detection
    urls = re.findall(r'https?://\S+', body)

    for url in urls:
        if not validators.url(url):
            score += 10
            reasons.append("Invalid URL detected")

    # Fake Sender
    trusted = [
        "gmail.com",
        "outlook.com",
        "yahoo.com"
    ]

    if "@" in sender:
        domain = sender.split("@")[1]
        if domain not in trusted:
            score += 20
            reasons.append("Unknown sender domain")

    # Excessive Capital Letters
    if body.isupper():
        score += 10
        reasons.append("Entire email is in capital letters")

    # Too Many Exclamation Marks
    if body.count("!") > 5:
        score += 10
        reasons.append("Too many exclamation marks")

    if score > 100:
        score = 100

    if score >= 70:
        risk = "High Risk"
    elif score >= 40:
        risk = "Medium Risk"
    else:
        risk = "Low Risk"

    return score, risk, reasons

import re

def highlight_text(body):

    keywords = [
        "verify",
        "login",
        "password",
        "urgent",
        "bank",
        "account",
        "click",
        "free",
        "winner",
        "otp",
        "refund",
        "invoice"
    ]

    highlighted = body

    for word in keywords:
        pattern = re.compile(word, re.IGNORECASE)
        highlighted = pattern.sub(
            f"<span style='background-color:red;color:white;padding:2px;border-radius:4px;'>{word}</span>",
            highlighted
        )

    return highlighted

# -------------------------------
# Routes
# -------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    print("step 1")

    sender = request.form["sender"]
    subject = request.form["subject"]
    body = request.form["body"]
    print("step 2")

    score, risk, reasons = analyze_email(sender, subject, body)
    print("step 3")
    highlighted_body = highlight_text(body)
    body=highlighted_body
    print("step 4")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    print("step 5")

    cursor.execute(
        "INSERT INTO history(sender,subject,score,risk) VALUES(?,?,?,?)",
        (sender, subject, score, risk)
    )

    conn.commit()
    conn.close()
    print("step 6")

    return render_template(
        "result.html",
        sender=sender,
        subject=subject,
        body=highlighted_body,
        score=score,
        risk=risk,
        reasons=reasons
    )


@app.route("/history")
def history():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM history ORDER BY id DESC")
    data = cursor.fetchall()

    conn.close()

    return render_template("history.html", emails=data)


@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM history")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM history WHERE risk='High Risk'")
    high = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM history WHERE risk='Medium Risk'")
    medium = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM history WHERE risk='Low Risk'")
    low = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        high=high,
        medium=medium,
        low=low
    )
@app.route("/quiz")
def quiz():
    return render_template("quiz.html")
@app.route("/download_report")
def download_report():

    sender = request.args.get("sender", "")
    subject = request.args.get("subject", "")
    risk = request.args.get("risk", "")
    score = request.args.get("score", "")

    buffer = io.BytesIO()

    pdf = canvas.Canvas(buffer)

    pdf.setFont("Helvetica-Bold",18)
    pdf.drawString(180,800,"PhishGuard Report")

    pdf.setFont("Helvetica",12)

    pdf.drawString(50,760,f"Sender : {sender}")
    pdf.drawString(50,730,f"Subject : {subject}")
    pdf.drawString(50,700,f"Risk Level : {risk}")
    pdf.drawString(50,670,f"Risk Score : {score}/100")

    pdf.drawString(50,620,"Recommendations")

    pdf.drawString(70,590,"• Don't click suspicious links.")
    pdf.drawString(70,565,"• Verify sender before replying.")
    pdf.drawString(70,540,"• Never share OTP or password.")
    pdf.drawString(70,515,"• Report suspicious emails.")

    pdf.save()

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="PhishGuard_Report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)