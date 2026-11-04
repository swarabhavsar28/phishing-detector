from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# 🔥 USE RELIABLE DATASET (EXISTS)
dataset = load_dataset("SetFit/enron_spam")

# rename label column
dataset = dataset.rename_column("label", "labels")

# split
dataset = dataset["train"].train_test_split(test_size=0.2)

# 🔥 use more data (not tiny)
dataset["train"] = dataset["train"].shuffle(seed=42).select(range(6000))
dataset["test"] = dataset["test"].shuffle(seed=42).select(range(1500))

# model
model_name = "distilbert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)

def tokenize(example):
    return tokenizer(
        example["text"],
        truncation=True,
        padding="max_length",
        max_length=256
    )

dataset = dataset.map(tokenize, batched=True)

dataset.set_format(type="torch", columns=["input_ids", "attention_mask", "labels"])

model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

# metrics
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="binary")
    acc = accuracy_score(labels, preds)
    return {
        "accuracy": acc,
        "f1": f1,
        "precision": precision,
        "recall": recall
    }

training_args = TrainingArguments(
    output_dir="./results",
    num_train_epochs=3,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset["train"],
    eval_dataset=dataset["test"],
    compute_metrics=compute_metrics
)

# train
trainer.train()

# evaluate
results = trainer.evaluate()
print(results)

# save
model.save_pretrained("model/hf_model")
tokenizer.save_pretrained("model/hf_model")

print("✅ Model trained successfully")