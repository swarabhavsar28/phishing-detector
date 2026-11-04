import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from utils.predictor import predict_email

# ===== SAMPLE TEST DATA =====
emails = [
    "Congratulations! You won a $1000 gift card. Click now",
    "Urgent: verify your bank account immediately",
    "Meeting tomorrow at 10am",
    "Update your password to avoid suspension",
    "Lunch plan today?",
    "Claim your free reward now",
    "Project discussion scheduled",
]

true_labels = [1,1,0,1,0,1,0]  # 1 = phishing, 0 = safe

pred_labels = []
scores = []

for email in emails:
    result = predict_email(email)
    score = result["risk_score"]

    scores.append(score)
    pred_labels.append(1 if score >= 50 else 0)

# ===== 1. METRICS BAR GRAPH =====
accuracy = np.mean(np.array(pred_labels) == np.array(true_labels))

precision = sum((np.array(pred_labels)==1) & (np.array(true_labels)==1)) / max(sum(np.array(pred_labels)==1),1)
recall = sum((np.array(pred_labels)==1) & (np.array(true_labels)==1)) / max(sum(np.array(true_labels)==1),1)

f1 = 2 * precision * recall / max((precision + recall),1)

metrics = [accuracy, precision, recall, f1]
labels = ["Accuracy", "Precision", "Recall", "F1"]

plt.figure()
plt.bar(labels, metrics)
plt.title("Model Performance")
plt.savefig("graph_metrics.png")

# ===== 2. CONFUSION MATRIX =====
cm = confusion_matrix(true_labels, pred_labels)

disp = ConfusionMatrixDisplay(confusion_matrix=cm)
disp.plot()
plt.title("Confusion Matrix")
plt.savefig("graph_confusion.png")

# ===== 3. RISK SCORE DISTRIBUTION =====
plt.figure()
plt.hist(scores, bins=5)
plt.title("Risk Score Distribution")
plt.savefig("graph_distribution.png")

# ===== 4. KEYWORD FREQUENCY =====
keywords = ["verify", "bank", "click", "password", "urgent", "free", "claim"]
counts = [2,1,2,1,1,1,2]  # dummy counts (or extract dynamically)

plt.figure()
plt.bar(keywords, counts)
plt.title("Keyword Frequency")
plt.savefig("graph_keywords.png")

print("✅ Graphs generated successfully")