from flask import Flask, render_template, request
from utils.predictor import predict_email

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    email_text = ""
    data = None

    if request.method == "POST":
        email_text = request.form.get("email", "")
        if email_text.strip():
            data = predict_email(email_text)

    return render_template("index.html", data=data, email_text=email_text)

if __name__ == "__main__":
    app.run(debug=True)