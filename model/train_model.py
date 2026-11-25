"""Compare local email classifiers on one duplicate-aware held-out split.

Expected dataset: dataset/emails.csv with columns: text,label
Supported labels: safe, suspicious, fraudulent

The held-out split is not used to fit TF-IDF or any classifier. The chosen
classifier is then refit on all labeled data for use by app.py.
"""

import csv
import json
import os
import re
import sys
import tempfile
from collections import Counter
from difflib import SequenceMatcher

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import FeatureUnion
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

# Use the same thresholds and warning-signal policy as the live app during
# evaluation, so reported predictions match the behavior users will see.
from app import classify_email

DATASET_PATH = os.path.join(PROJECT_DIR, "dataset", "emails.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")
MODEL_BUNDLE_PATH = os.path.join(BASE_DIR, "model_bundle.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "metrics.json")
LABELS = ["safe", "suspicious", "fraudulent"]
NEAR_DUPLICATE_THRESHOLD = 0.90


def load_dataset(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            "Make sure dataset/emails.csv exists in your project."
        )

    rows = []
    with open(path, "r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        required = {"text", "label"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError("CSV must contain these columns: text,label")

        for row in reader:
            text = (row.get("text") or "").strip()
            label = (row.get("label") or "").strip().lower()
            if text and label in LABELS:
                rows.append((text, label))

    unique_rows = list(dict.fromkeys(rows))
    if len(unique_rows) < len(rows):
        print(f"Removed {len(rows) - len(unique_rows)} exact duplicate row(s).")

    if len(unique_rows) < 30:
        raise ValueError(
            f"Only {len(unique_rows)} valid unique rows found. Add more labeled examples first."
        )

    counts = Counter(label for _, label in unique_rows)
    missing = [label for label in LABELS if counts[label] < 4]
    if missing:
        raise ValueError(
            "Need at least 4 examples per label for a stratified 4-fold holdout. "
            f"Insufficient labels: {', '.join(missing)}"
        )

    return [text for text, _ in unique_rows], [label for _, label in unique_rows], counts


def make_near_duplicate_groups(texts, threshold=NEAR_DUPLICATE_THRESHOLD):
    """Group exact/near-duplicate text so related rows stay in one split."""
    normalized = [
        re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", text.casefold())).strip()
        for text in texts
    ]
    parent = list(range(len(texts)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left, right):
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    near_duplicate_pairs = 0
    for left in range(len(normalized)):
        for right in range(left + 1, len(normalized)):
            a, b = normalized[left], normalized[right]
            if not a or not b:
                continue
            # A ratio above the threshold is impossible when normalized lengths
            # differ too much, so skip the comparatively expensive matcher.
            if min(len(a), len(b)) / max(len(a), len(b)) < threshold * 0.85:
                continue
            if SequenceMatcher(None, a, b, autojunk=False).ratio() >= threshold:
                union(left, right)
                near_duplicate_pairs += 1

    root_to_group = {}
    groups = []
    for index in range(len(texts)):
        root = find(index)
        if root not in root_to_group:
            root_to_group[root] = len(root_to_group)
        groups.append(root_to_group[root])
    return groups, near_duplicate_pairs


def make_vectorizer(include_char_features):
    word_vectorizer = TfidfVectorizer(
        strip_accents="unicode",
        lowercase=True,
        sublinear_tf=True,
        max_features=10000,
        ngram_range=(1, 2),
        min_df=1,
    )
    if not include_char_features:
        return word_vectorizer

    char_vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        strip_accents="unicode",
        lowercase=True,
        sublinear_tf=True,
        max_features=20000,
        ngram_range=(3, 5),
        min_df=2,
    )
    return FeatureUnion([
        ("word", word_vectorizer),
        ("character", char_vectorizer),
    ])


def make_candidates():
    return {
        "Logistic Regression": LogisticRegression(
            max_iter=3000, class_weight="balanced", C=2.0, random_state=42
        ),
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.5),
        "Calibrated Linear SVM": CalibratedClassifierCV(
            estimator=LinearSVC(class_weight="balanced", C=1.0, random_state=42),
            method="sigmoid",
            cv=3,
        ),
    }


def _atomic_dump(value, destination, dump_json=False):
    fd, temporary_path = tempfile.mkstemp(prefix=".training-", dir=BASE_DIR)
    os.close(fd)
    try:
        if dump_json:
            with open(temporary_path, "w", encoding="utf-8") as file:
                json.dump(value, file, indent=2)
        else:
            joblib.dump(value, temporary_path)
        os.replace(temporary_path, destination)
    finally:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)


def main():
    texts, labels, counts = load_dataset(DATASET_PATH)
    groups, duplicate_pairs = make_near_duplicate_groups(texts)
    splitter = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=42)
    train_indices, test_indices = next(splitter.split(texts, labels, groups))

    X_train_text = [texts[index] for index in train_indices]
    X_test_text = [texts[index] for index in test_indices]
    y_train = [labels[index] for index in train_indices]
    y_test = [labels[index] for index in test_indices]
    train_groups = {groups[index] for index in train_indices}
    test_groups = {groups[index] for index in test_indices}
    if train_groups & test_groups:
        raise RuntimeError("Duplicate-group leakage detected in the evaluation split.")
    if set(y_train) != set(LABELS) or set(y_test) != set(LABELS):
        raise ValueError("The stratified holdout must contain all three labels in train and test.")

    print(f"Dataset rows: {len(texts)}; class counts: {dict(counts)}")
    print(f"Near-duplicate pairs grouped: {duplicate_pairs}")
    print(f"Train rows: {len(train_indices)}; held-out rows: {len(test_indices)}")
    print("Held-out class counts:", dict(Counter(y_test)))

    candidate_results = {}
    trained_candidates = {}
    best_name = None
    best_rank = None

    for feature_name, include_char in [
        ("word TF-IDF", False),
        ("word + character TF-IDF", True),
    ]:
        vectorizer = make_vectorizer(include_char)
        train_matrix = vectorizer.fit_transform(X_train_text)
        test_matrix = vectorizer.transform(X_test_text)

        for model_name, estimator in make_candidates().items():
            estimator.fit(train_matrix, y_train)
            predictions = [
                classify_email(estimator, vectorizer, "", "", text)[0]
                for text in X_test_text
            ]
            report = classification_report(
                y_test, predictions, labels=LABELS, output_dict=True, zero_division=0
            )
            matrix = confusion_matrix(y_test, predictions, labels=LABELS)
            accuracy = float(accuracy_score(y_test, predictions))
            macro_f1 = float(f1_score(y_test, predictions, labels=LABELS,
                                      average="macro", zero_division=0))
            safe_as_fraudulent = int(matrix[0, 2])
            fraudulent_as_safe = int(matrix[2, 0])
            candidate_name = f"{feature_name} + {model_name}"
            candidate_results[candidate_name] = {
                "accuracy": round(accuracy, 4),
                "macro_precision": round(float(report["macro avg"]["precision"]), 4),
                "macro_recall": round(float(report["macro avg"]["recall"]), 4),
                "macro_f1": round(macro_f1, 4),
                "per_class": {
                    label: {
                        "precision": round(float(report[label]["precision"]), 4),
                        "recall": round(float(report[label]["recall"]), 4),
                        "f1": round(float(report[label]["f1-score"]), 4),
                        "support": int(report[label]["support"]),
                    }
                    for label in LABELS
                },
                "confusion_matrix": matrix.tolist(),
                "confusion_matrix_order": LABELS,
                "safe_misclassified_as_fraudulent": safe_as_fraudulent,
                "fraudulent_misclassified_as_safe": fraudulent_as_safe,
            }
            trained_candidates[candidate_name] = (vectorizer, estimator, include_char, model_name)

            # Macro-F1 leads selection; ties prefer fewer costly safe-to-fraud
            # and fraud-to-safe errors, then higher accuracy.
            rank = (macro_f1, -safe_as_fraudulent, -fraudulent_as_safe, accuracy)
            if best_rank is None or rank > best_rank:
                best_name, best_rank = candidate_name, rank

            print(
                f"{candidate_name}: accuracy={accuracy:.3f}, macro-F1={macro_f1:.3f}, "
                f"safe->fraud={safe_as_fraudulent}, fraud->safe={fraudulent_as_safe}"
            )

    selected_result = candidate_results[best_name]
    _, _, include_char, selected_model_name = trained_candidates[best_name]
    final_vectorizer = make_vectorizer(include_char)
    final_matrix = final_vectorizer.fit_transform(texts)
    final_model = make_candidates()[selected_model_name]
    final_model.fit(final_matrix, labels)

    metrics = {
        "selected_model": best_name,
        "best_model": best_name,
        "selection_metric": "held_out_macro_f1_then_targeted_error_counts_then_accuracy",
        "dataset_rows_after_deduplication": len(texts),
        "train_rows": len(train_indices),
        "test_rows": len(test_indices),
        "near_duplicate_threshold": NEAR_DUPLICATE_THRESHOLD,
        "near_duplicate_pairs_grouped": duplicate_pairs,
        "class_order": LABELS,
        "class_counts": dict(counts),
        "held_out_class_counts": dict(Counter(y_test)),
        "candidate_results": candidate_results,
        "accuracy": selected_result["accuracy"],
        "macro_precision": selected_result["macro_precision"],
        "macro_recall": selected_result["macro_recall"],
        "macro_f1": selected_result["macro_f1"],
        "per_class": selected_result["per_class"],
        "confusion_matrix": selected_result["confusion_matrix"],
        "confusion_matrix_order": LABELS,
        "safe_misclassified_as_fraudulent": selected_result["safe_misclassified_as_fraudulent"],
        "fraudulent_misclassified_as_safe": selected_result["fraudulent_misclassified_as_safe"],
        # Keep the dashboard/admin display shape used by the current templates.
        "models": {
            name: {
                "accuracy": round(result["accuracy"] * 100, 1),
                "macro_f1": round(result["macro_f1"] * 100, 1),
            }
            for name, result in candidate_results.items()
        },
        "note": (
            "All candidates use the same duplicate-aware stratified held-out split. "
            "TF-IDF and classifiers are fit on training rows only during evaluation. "
            "The held-out results are also used to compare/select among candidates, so the "
            "selected score is not an independent final estimate. Dataset size is small and "
            "does not establish real-world performance. Model scores are not verified fraud "
            "probabilities. Predictions use the same review and contextual-fraud policy as app.py."
        ),
    }

    os.makedirs(BASE_DIR, exist_ok=True)
    # The app prefers this single atomic bundle, keeping model and vectorizer
    # paired even if a retraining process is interrupted while writing legacy files.
    bundle = {"model": final_model, "vectorizer": final_vectorizer, "metrics": metrics}
    _atomic_dump(bundle, MODEL_BUNDLE_PATH)
    _atomic_dump(final_model, MODEL_PATH)
    _atomic_dump(final_vectorizer, VECTORIZER_PATH)
    _atomic_dump(metrics, METRICS_PATH, dump_json=True)

    print("\nSelected model:", best_name)
    print("Selected held-out per-class results:", selected_result["per_class"])
    print("Selected confusion matrix (rows actual; columns predicted):")
    print(selected_result["confusion_matrix"])
    print("Saved model bundle:", MODEL_BUNDLE_PATH)
    print("Saved legacy model/vectorizer and metrics artifacts.")


if __name__ == "__main__":
    main()
