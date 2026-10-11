from features import extract_features, FEATURE_NAMES

# أوزان مكتوبة باليد (قبل PSO) وحد فاصل
DEFAULT_WEIGHTS = [0.5, 0.3, 1.5, 1.5, 0.5, 1.0, 1.0, 0.5, 0.3, 1.0]
DEFAULT_THRESHOLD = 1.5


class PhishingAgent:
    def __init__(self, weights=None, threshold=None):
        self.weights = list(weights) if weights is not None else list(DEFAULT_WEIGHTS)
        self.threshold = DEFAULT_THRESHOLD if threshold is None else threshold

    def decide(self, url):
        feats = extract_features(url)
        contributions = [w * f for w, f in zip(self.weights, feats)]
        score = sum(contributions)
        verdict = "PHISHING" if score > self.threshold else "SAFE"

        # أهم الأسباب (العلامات اللي زوّدت الدرجة)
        reasons = sorted(
            [(c, n) for c, n in zip(contributions, FEATURE_NAMES) if c > 0],
            reverse=True,
        )
        return verdict, score, [n for c, n in reasons[:3]]