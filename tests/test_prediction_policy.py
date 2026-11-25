import unittest

import numpy as np
from app import classify_email, model as saved_model, vectorizer as saved_vectorizer
from model.train_model import make_near_duplicate_groups
from sklearn.model_selection import StratifiedGroupKFold


class FixedVectorizer:
    def transform(self, texts):
        return texts


class FixedModel:
    classes_ = ["fraudulent", "safe", "suspicious"]

    def __init__(self, probabilities):
        self.probabilities = probabilities

    def predict_proba(self, _features):
        return np.asarray([self.probabilities])


class PredictionPolicyTests(unittest.TestCase):
    def test_single_words_alone_cannot_trigger_fraudulent(self):
        model = FixedModel([0.99, 0.005, 0.005])
        for word in ("urgent", "free", "password", "scholarship"):
            with self.subTest(word=word):
                label, _ = classify_email(model, FixedVectorizer(), "", "", word)
                self.assertNotEqual(label, "fraudulent")

    def test_saved_model_does_not_mark_individual_terms_fraudulent(self):
        self.assertIsNotNone(saved_model)
        self.assertIsNotNone(saved_vectorizer)
        for word in ("urgent", "free", "password", "scholarship"):
            with self.subTest(word=word):
                label, _ = classify_email(saved_model, saved_vectorizer, "", "", word)
                self.assertNotEqual(label, "fraudulent")

    def test_contextual_credential_request_can_be_fraudulent(self):
        model = FixedModel([0.20, 0.40, 0.40])
        label, _ = classify_email(
            model, FixedVectorizer(), "", "Action required", "Send us your password now."
        )
        self.assertEqual(label, "fraudulent")

    def test_model_fraud_with_multiple_message_signals_can_be_fraudulent(self):
        model = FixedModel([0.95, 0.02, 0.03])
        label, _ = classify_email(
            model,
            FixedVectorizer(),
            "sender@example.test",
            "Urgent account action",
            "Click https://example.test/login immediately.",
        )
        self.assertEqual(label, "fraudulent")

    def test_uncertain_predictions_and_failed_authentication_go_to_review(self):
        uncertain_safe = FixedModel([0.10, 0.62, 0.28])
        label, _ = classify_email(uncertain_safe, FixedVectorizer(), "", "", "A note")
        self.assertEqual(label, "suspicious")

        confident_safe = FixedModel([0.01, 0.97, 0.02])
        label, _ = classify_email(
            confident_safe, FixedVectorizer(), "", "", "A note", authentication={"spf": "fail"}
        )
        self.assertEqual(label, "suspicious")

    def test_near_duplicates_stay_in_the_same_split_group(self):
        texts = [
            "Please verify your account at https://example.test now",
            "Please verify your account at https://example.test now!",
            "Team lunch is scheduled for Friday afternoon.",
            "The quarterly finance report is attached for review.",
            "Your account requires urgent password verification immediately.",
            "We received your payment and will send a receipt.",
            "Click this link to claim your prize today.",
            "The meeting agenda is available in the shared folder.",
            "Your package delivery is scheduled for tomorrow.",
            "Send your one-time code to restore access immediately.",
            "Please review the attached project milestones.",
            "A security alert was generated for your account.",
        ]
        labels = ["fraudulent", "fraudulent", "safe", "safe", "fraudulent", "safe",
                  "fraudulent", "safe", "suspicious", "fraudulent", "suspicious", "suspicious"]
        groups, _ = make_near_duplicate_groups(texts)
        self.assertEqual(groups[0], groups[1])

        splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
        for train, test in splitter.split(texts, labels, groups):
            self.assertFalse(set(groups[index] for index in train)
                             & set(groups[index] for index in test))


if __name__ == "__main__":
    unittest.main()
