"""Shared helpers for the anomaly-detection algorithm scripts.

Provides data loading / feature selection (`get_trainable_data`), small metric
helpers (`r2`, `r3`, `count_stat`) and the result-serialisation helpers that
each algorithm uses to write its `*_metrics_long.csv` file.

Output locations are repo-relative (under `outputs/`); override the base with
the ``PG_OUTPUT_DIR`` environment variable.
"""
import os
import csv
import re
from typing import Literal, Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, StandardScaler  # noqa: F401

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LABEL_COL = "attack"

# Metric column written / consumed downstream (e.g. the Friedman analysis).
col_name = "MCC"

# Output locations (repo-relative; override with PG_OUTPUT_DIR).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OUTPUT_BASE = os.environ.get("PG_OUTPUT_DIR") or os.path.join(_REPO_ROOT, "outputs")

ROOT_OUTPUT_DIR = os.path.join(_OUTPUT_BASE, "results_aggregate")
PLOT_DATA_DIR = os.path.join(_OUTPUT_BASE, "Algorithm_wise_plots_data")
PLOTS_DIR = os.path.join(_OUTPUT_BASE, "Algorithm_wise_plots")
LOG_DIR = os.path.join(_OUTPUT_BASE, "logs")
LOG_FILE = os.path.join(LOG_DIR, "all_run.log")

os.makedirs(PLOT_DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Column order of the per-algorithm `*_metrics_long.csv` files.
PLOT_FIELDS_ORDER = [
    "Algorithm", "Dataset", "GoID", "Attack_Scn", "Split", "Run",
    "Normal count", "Attack count", "Total", "tp", "tn", "fp", "fn",
    "Accuracy %", "Precision_anom %", "Precision %", "Recall_anom %", "Recall %",
    "F1-Score_anom %", "F1-Score %", "BalancedAcc %", "MCC", "PR-AUC", "ROC-AUC",
    "TotalTime (ms)", "AvgTimePerPacket(ns)", "Ram_usage", "CPU_avg%", "CPU_peak%",
    "training_time_ms", "training_avg_time_per_packet_ns", "training_peak_ram_mb",
    "training_cpu_avg_pct", "training_cpu_peak_pct", "n_train_attack", "n_train_normal",
]


# ---------------------------------------------------------------------------
# Numeric helpers
# ---------------------------------------------------------------------------
def r3(x):
    try:
        return round(float(x), 3)
    except Exception as e:  # noqa: BLE001
        return e


def r2(x):
    try:
        return round(float(x), 2)
    except Exception as e:  # noqa: BLE001
        return e


def count_stat(vector):
    """Count occurrences of each label value (expects 0/1 labels)."""
    unique, counts = np.unique(vector, return_counts=True)
    return dict(zip(unique, counts))


def _as_float(x):
    if x is None:
        return None
    s = str(x).replace(" MB", "").replace(",", "").strip()
    try:
        return float(s)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Data cleaning / feature selection
# ---------------------------------------------------------------------------
def _sanitize_to_numeric(df: pd.DataFrame, label_col: str = LABEL_COL) -> pd.DataFrame:
    """Coerce booleans / boolean-like / numeric-as-string columns to numerics."""
    df = df.copy()

    bool_cols = df.select_dtypes(include=["bool"]).columns
    if len(bool_cols) > 0:
        df[bool_cols] = df[bool_cols].astype(int)

    for col in df.select_dtypes(include=["object"]).columns:
        s = df[col].astype(str).str.strip().str.lower()
        s.replace({"": 0, "nan": 0, "none": 0}, inplace=True)
        if s.isin(["True", "False", "1", "0"]).all():
            df[col] = s.map({"True": 1, "False": 0, "1": 1, "0": 0}).astype(float)
        else:
            df[col] = pd.to_numeric(s, errors="coerce")

    if label_col in df.columns:
        lab = df[label_col]
        if lab.dtype == "bool":
            df[label_col] = lab.astype(int)
        elif lab.dtype == object:
            s = lab.astype(str).str.strip().str.lower()
            s.replace({"": 0, "nan": 0, "none": 0}, inplace=True)
            if s.isin(["true", "false", "1", "0"]).all():
                df[label_col] = s.map({"true": 1, "false": 0, "1": 1, "0": 0}).astype("Int64")
            else:
                df[label_col] = pd.to_numeric(s, errors="coerce").astype("Int64")

    return df


def get_selected_small(feat_cols):
    selected = ["Length", "stNum", "sqNum", "timeAllowedtoLive",
                "numDatSetEntries", "time_diff", "stNum_diff", "sqNum_diff"]
    for col in feat_cols:
        if "boolean" in col or "bitstring" in col:
            selected.append(col)
    return selected


def get_selected_4(feat_cols):
    selected = ["Length", "stNum", "sqNum", "timeAllowedtoLive",
                "numDatSetEntries", "time_diff", "stNum_diff", "sqNum_diff"]
    for col in feat_cols:
        if "bitstring_diff" in col or "boolean_diff" in col:
            selected.append(col)
    return selected


def get_selected_features(feat_columns):
    pattern = (r"^(?:(?:Length|stNum|sqNum|timeAllowedtoLive|numDatSetEntries|"
               r"time_diff|stNum_diff|sqNum_diff|bitstring_\d+|floatvalue_\d+|bool.*|int.*))$")
    return [c for c in feat_columns if re.match(pattern, c)]


def get_only_derived_features(feat_columns):
    pattern = r"^(?:attack|index|time_diff|timestamp_diff|Length_diff|stNum_diff|sqNum_diff|.*_diff)$"
    return [c for c in feat_columns if re.match(pattern, c)]


def get_selected_3(feat_columns):
    return ["Length", "stNum", "sqNum", "timeAllowedtoLive",
            "numDatSetEntries", "time_diff", "stNum_diff", "sqNum_diff"]


def get_original_features(feat_columns):
    selected = ["Length", "timeAllowedtoLive", "numDatSetEntries",
                "time_diff", "stNum_diff", "sqNum_diff"]
    for col in feat_columns:
        if "int" in col or "float" in col:
            selected.append(col)
    return selected


def get_clean_data_from_dataframe(df: pd.DataFrame, use_freq=False, use_features="all"):
    """Return ``(X, y, feat_cols, df_clean)`` with X float64 and y int."""
    df_clean = _sanitize_to_numeric(df)

    feat_cols = df_clean.select_dtypes(include=[np.number]).columns.tolist()
    for drop in (LABEL_COL, "index"):
        if drop in feat_cols:
            feat_cols.remove(drop)

    if use_features == "derived":
        feat_cols = get_only_derived_features(feat_cols)
    elif use_features == "selected_1":
        feat_cols = get_selected_features(feat_cols)
    elif use_features == "selected_2":
        feat_cols = get_selected_small(feat_cols)
    elif use_features == "selected_3":
        feat_cols = get_selected_3(feat_cols)
    elif use_features == "selected_4":
        feat_cols = get_selected_4(feat_cols)
    elif use_features == "original":
        feat_cols = get_original_features(feat_cols)

    if use_freq:
        feat_cols.append("freq")

    X = df_clean[feat_cols].astype(float).to_numpy(copy=False)
    y_series = df_clean[LABEL_COL] if LABEL_COL in df_clean.columns else None

    mask = ~np.isnan(X).any(axis=1)
    df_clean = df_clean[mask].reset_index(drop=True)
    if y_series is not None:
        mask &= y_series.notna().to_numpy()

    X = X[mask].astype(np.float64, copy=False)
    y = y_series[mask].astype(int).to_numpy() if y_series is not None else None
    return X, y, feat_cols, df_clean


def get_trainable_data(
    df_train: Optional[pd.DataFrame] = None,
    df_val: Optional[pd.DataFrame] = None,
    df_test: Optional[pd.DataFrame] = None,
    scaled_input: bool = True,
    use_freq: bool = False,
    use_features: Literal["original", "derived", "selected", "all"] = "original",
    scaler: Optional[MinMaxScaler] = None,
):
    X_train = y_train = df_clean_train = None
    X_val = y_val = df_clean_val = None
    X_test = y_test = df_clean_test = None
    feat_cols = None

    if df_train is not None:
        X_train, y_train, feat_cols, df_clean_train = get_clean_data_from_dataframe(
            df_train, use_features=use_features, use_freq=use_freq)
    if df_val is not None:
        X_val, y_val, feat_cols, df_clean_val = get_clean_data_from_dataframe(
            df_val, use_features=use_features, use_freq=use_freq)
    if df_test is not None:
        X_test, y_test, feat_cols, df_clean_test = get_clean_data_from_dataframe(
            df_test, use_features=use_features, use_freq=use_freq)

    if scaler is not None:
        X_train = scaler.transform(X_train) if X_train is not None else None
        X_val = scaler.transform(X_val) if X_val is not None else None
        X_test = scaler.transform(X_test) if X_test is not None else None
    elif scaled_input:
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train) if X_train is not None else None
        X_val = scaler.transform(X_val) if X_val is not None else None
        X_test = scaler.transform(X_test) if X_test is not None else None

    return (X_train, X_val, X_test, y_train, y_val, y_test,
            df_clean_train, df_clean_val, df_clean_test, feat_cols)


# ---------------------------------------------------------------------------
# Result serialisation
# ---------------------------------------------------------------------------
def append_results_to_csv(csv_path, results_data, hierarchy_info):
    """Append raw sectioned (Test) results to an audit CSV."""
    if not results_data:
        return
    with open(csv_path, "a", newline="") as f:
        w = csv.writer(f)
        w.writerow([])
        w.writerow(["Dataset:", hierarchy_info["dataset"]])
        w.writerow(["GoID:", hierarchy_info["goid"]])
        w.writerow(["Attack_Type:", hierarchy_info["attack_type"]])
        w.writerow([])
        first_run_data = next(iter(results_data.values()))
        for section in ["Test"]:
            if section in first_run_data:
                headers = list(first_run_data[section].keys())
                w.writerow([f"{section}:"] + headers)
                for run_key, run_data in results_data.items():
                    if section in run_data:
                        w.writerow([run_key] + list(run_data[section].values()))
                w.writerow([])


def extract_plot_rows(all_runs_results, algorithm, dataset_info):
    """One row per run (Test split) for the metrics_long CSV."""
    rows = []
    for run_key, sections in all_runs_results.items():
        split = "Test"
        s = sections[split]
        rows.append({
            "Algorithm": algorithm,
            "Dataset": dataset_info["dataset"],
            "GoID": dataset_info["goid"],
            "Attack_Scn": dataset_info["attack_type"],
            "Split": split,
            "Run": run_key,
            "Accuracy %": _as_float(s.get("Accuracy %")),
            "Precision %": _as_float(s.get("Precision %")),
            "Recall %": _as_float(s.get("Recall %")),
            "F1-Score %": _as_float(s.get("F1-Score %")),
            "Precision_anom %": _as_float(s.get("Precision_anom %")),
            "Recall_anom %": _as_float(s.get("Recall_anom %")),
            "F1-Score_anom %": _as_float(s.get("F1-Score_anom %")),
            "BalancedAcc %": _as_float(s.get("BalancedAcc %")),
            "MCC": _as_float(s.get("MCC")),
            "PR-AUC": _as_float(s.get("PR-AUC")),
            "ROC-AUC": _as_float(s.get("ROC-AUC")),
            "tp": _as_float(s.get("tp")),
            "tn": _as_float(s.get("tn")),
            "fp": _as_float(s.get("fp")),
            "fn": _as_float(s.get("fn")),
            "Normal count": _as_float(s.get("Normal count")),
            "Attack count": _as_float(s.get("Attack count")),
            "Total": _as_float(s.get("Total")),
            "TotalTime (ms)": r3(_as_float(s.get("TotalTime (ms)"))),
            "AvgTimePerPacket(ns)": r3(_as_float(s.get("AvgTimePerPacket(ns)"))),
            "CPU_avg%": r3(_as_float(s.get("CPU_avg%"))),
            "CPU_peak%": r3(_as_float(s.get("CPU_peak%"))),
            "Ram_usage": r3(_as_float(s.get("Ram_usage"))),
            "training_time_ms": r3(_as_float(s.get("training_time_ms"))),
            "training_avg_time_per_packet_ns": r3(_as_float(s.get("training_avg_time_per_packet_ns"))),
            "training_peak_ram_mb": r3(_as_float(s.get("training_peak_ram_mb"))),
            "training_cpu_avg_pct": r3(_as_float(s.get("training_cpu_avg_pct"))),
            "training_cpu_peak_pct": r3(_as_float(s.get("training_cpu_peak_pct"))),
            "n_train_attack": r3(_as_float(s.get("n_train_attack"))),
            "n_train_normal": r3(_as_float(s.get("n_train_normal"))),
        })
    return rows


def extract_average_rows_over_runs(all_runs_results, algorithm, dataset_info):
    """One `Average` row summarising all runs (Test split)."""
    split = "Test"
    acc, prec, rec, f1 = [], [], [], []
    prec_anom, rec_anom, f1_anom = [], [], []
    balanced_acc, mcc, pr_auc, roc_auc = [], [], [], []
    ttime, avgpkt = [], []
    tp, tn, fp, fn = [], [], [], []
    n_norm, n_att, n_tot = [], [], []
    cpu_usg, cpu_peak, ram_usage = [], [], []
    training_time, training_avgpkt = [], []
    training_peak_ram, training_cpu_avg, training_cpu_peak = [], [], []
    n_train_attack, n_train_normal = [], []

    for _, sections in all_runs_results.items():
        if split not in sections:
            continue
        s = sections[split]

        def add(lst, key):
            v = _as_float(s.get(key))
            if v is not None:
                lst.append(v)

        add(acc, "Accuracy %"); add(prec, "Precision %")
        add(rec, "Recall %"); add(f1, "F1-Score %")
        add(prec_anom, "Precision_anom %"); add(rec_anom, "Recall_anom %")
        add(f1_anom, "F1-Score_anom %"); add(balanced_acc, "BalancedAcc %")
        add(mcc, "MCC"); add(pr_auc, "PR-AUC"); add(roc_auc, "ROC-AUC")
        add(ttime, "TotalTime (ms)"); add(avgpkt, "AvgTimePerPacket(ns)")
        add(tp, "tp"); add(tn, "tn"); add(fp, "fp"); add(fn, "fn")
        add(n_norm, "Normal count"); add(n_att, "Attack count"); add(n_tot, "Total")
        add(cpu_usg, "CPU_avg%"); add(cpu_peak, "CPU_peak%"); add(ram_usage, "Ram_usage")
        add(training_time, "training_time_ms")
        add(training_avgpkt, "training_avg_time_per_packet_ns")
        add(training_peak_ram, "training_peak_ram_mb")
        add(training_cpu_avg, "training_cpu_avg_pct")
        add(training_cpu_peak, "training_cpu_peak_pct")
        add(n_train_attack, "n_train_attack")
        add(n_train_normal, "n_train_normal")

    def mean_or_none(lst):
        return sum(lst) / len(lst) if lst else None

    def sum_or_none(lst):
        return sum(lst) if lst else None

    def max_or_none(lst):
        return max(lst) if lst else None

    return [{
        "Algorithm": algorithm,
        "Dataset": dataset_info["dataset"],
        "GoID": dataset_info["goid"],
        "Attack_Scn": dataset_info["attack_type"],
        "Split": split,
        "Run": "Average",
        "Accuracy %": r2(mean_or_none(acc)),
        "Precision %": r2(mean_or_none(prec)),
        "Recall %": r2(mean_or_none(rec)),
        "F1-Score %": r2(mean_or_none(f1)),
        "Precision_anom %": r2(mean_or_none(prec_anom)),
        "Recall_anom %": r2(mean_or_none(rec_anom)),
        "F1-Score_anom %": r2(mean_or_none(f1_anom)),
        "BalancedAcc %": r2(mean_or_none(balanced_acc)),
        "MCC": r3(mean_or_none(mcc)),
        "PR-AUC": r3(mean_or_none(pr_auc)),
        "ROC-AUC": r3(mean_or_none(roc_auc)),
        "tp": r3(sum_or_none(tp)),
        "tn": r3(sum_or_none(tn)),
        "fp": r3(sum_or_none(fp)),
        "fn": r3(sum_or_none(fn)),
        "Normal count": r3(sum_or_none(n_norm)),
        "Attack count": r3(sum_or_none(n_att)),
        "Total": r3(sum_or_none(n_tot)),
        "TotalTime (ms)": r3(mean_or_none(ttime)),
        "AvgTimePerPacket(ns)": r3(mean_or_none(avgpkt)),
        "CPU_avg%": r3(mean_or_none(cpu_usg)),
        "CPU_peak%": r3(mean_or_none(cpu_peak)),
        "Ram_usage": r3(mean_or_none(ram_usage)),
        "training_time_ms": r3(mean_or_none(training_time)),
        "training_avg_time_per_packet_ns": r3(mean_or_none(training_avgpkt)),
        "training_peak_ram_mb": r3(max_or_none(training_peak_ram)),
        "training_cpu_avg_pct": r3(mean_or_none(training_cpu_avg)),
        "training_cpu_peak_pct": r3(max_or_none(training_cpu_peak)),
        "n_train_attack": r3(sum_or_none(n_train_attack)),
        "n_train_normal": r3(sum_or_none(n_train_normal)),
    }]


def append_rows_to_long_csv(long_csv_path, rows):
    os.makedirs(os.path.dirname(long_csv_path), exist_ok=True)
    file_exists = os.path.exists(long_csv_path)
    with open(long_csv_path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=PLOT_FIELDS_ORDER)
        if not file_exists:
            w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, None) for k in PLOT_FIELDS_ORDER})
