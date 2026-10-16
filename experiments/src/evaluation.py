from functools import partial
from time import perf_counter
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import VarianceThreshold, SelectKBest, mutual_info_classif
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import (
    balanced_accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix, accuracy_score,
)


def model_pipeline(kind, seed, config, k=None):
    if kind == "logistic":
        classifier = LogisticRegression(C=config["logistic_C"], class_weight="balanced",
                                        max_iter=5000, random_state=seed)
    elif kind == "forest":
        classifier = RandomForestClassifier(
            n_estimators=config["forest_trees"], max_depth=config["forest_max_depth"],
            min_samples_leaf=config["forest_min_leaf"], class_weight="balanced",
            random_state=seed, n_jobs=config["n_jobs"])
    elif kind == "dummy":
        classifier = DummyClassifier(strategy="prior", random_state=seed)
    else: raise ValueError(kind)
    selector = SelectKBest(partial(mutual_info_classif, random_state=seed), k=k) if k else "passthrough"
    return Pipeline([
        ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
        ("variance", VarianceThreshold()),
        ("scale", StandardScaler()),
        ("select", selector),
        ("model", classifier),
    ])


def metrics(y, p):
    predicted = (p >= .5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y, predicted),
        "balanced_accuracy": balanced_accuracy_score(y, predicted),
        "precision": precision_score(y, predicted, zero_division=0),
        "recall": recall_score(y, predicted, zero_division=0),
        "f1": f1_score(y, predicted, zero_division=0),
        "roc_auc": roc_auc_score(y, p) if len(np.unique(y)) == 2 else np.nan,
        "average_precision": average_precision_score(y, p),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "test_normal": int((np.asarray(y) == 0).sum()),
        "test_execution": int((np.asarray(y) == 1).sum()),
    }, predicted


def fit_evaluate(xtrain, ytrain, xtest, ytest, kind, seed, config, k=None):
    model = model_pipeline(kind, seed, config, k)
    start = perf_counter()
    model.fit(xtrain, ytrain)
    fit_seconds = perf_counter() - start
    start = perf_counter()
    probability = model.predict_proba(xtest)[:, 1]
    prediction_seconds = perf_counter() - start
    result, predicted = metrics(ytest, probability)
    result.update({
        "fit_seconds": fit_seconds, "prediction_seconds": prediction_seconds,
        "input_features": xtrain.shape[1],
        "retained_features": len(model[:-1].get_feature_names_out()),
        "train_normal": int((np.asarray(ytrain) == 0).sum()),
        "train_execution": int((np.asarray(ytrain) == 1).sum()),
    })
    return model, result, probability, predicted
