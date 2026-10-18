#!/usr/bin/env python3
"""run_all.py - run every anomaly-detection algorithm over all datasets.

For each discovered dataset (a folder containing ``train/`` and ``test/`` CSVs)
this launches each algorithm in ``algorithms/`` as a subprocess. Every
algorithm writes its own ``<algo>_metrics_long.csv`` into the shared output
folder (``utility.unsupervised_helper.PLOT_DATA_DIR``); downstream statistical
analysis consumes those files separately.
"""
import os
import sys
import subprocess
import warnings

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(THIS_DIR)
sys.path.insert(0, REPO_ROOT)

from utility import unsupervised_helper as uh  # noqa: E402  (for PLOT_DATA_DIR)

ALGORITHMS_DIR = os.path.join(REPO_ROOT, "algorithms")

# ===========================================================================
#  CONFIGURATION
# ===========================================================================

# Dummy URL for the preprocessed dataset folder. Replace with the real download
# link, then download and extract it into DATA_ROOT.
DATA_URL = "https://example.com/REPLACE_WITH_DATASET_URL"

# Root folder holding the preprocessed datasets (see find_dataset_paths below).
DATA_ROOT = os.path.join(REPO_ROOT, "data", "preprocessed")

# Algorithms run by default (unsupervised). The supervised set below is kept
# for reference and can be swapped in.
UNSUPERVISED = [
    "iqr_mom", "iqr", "z_score",
    "pam", "clara", "optics", "singleLink", "ward", "spectral_clustering",
    "kmeans", "gmm", "hbos",
    "pca", "vae", "ae",
    "lof", "If", "ocsvm", "svdd",
]
SUPERVISED = [
    "LR", "NB", "DT", "RF", "XGB", "NN", "KNN", "SVM", "RNN", "CNN", "RNN_LSTM",
]


# ---------------------------------------------------------------------------
#  Dataset discovery
# ---------------------------------------------------------------------------
def find_dataset_paths(root_dir, validation=False):
    """Find every leaf dataset (a folder with both ``train`` and ``test``).

    Expected layout under ``root_dir``::

        <root>/<dataset>/<goid>/<attack_type>/train/{normal_only,attack_and_normal}.csv
        <root>/<dataset>/<goid>/<attack_type>/test/attack_and_normal.csv
    """
    all_paths = []
    if not os.path.isdir(root_dir):
        print(f"Error: root directory not found at '{root_dir}'")
        return all_paths

    for dirpath, dirnames, _files in os.walk(root_dir):
        if "train" not in dirnames or "test" not in dirnames:
            continue

        train_dir = os.path.join(dirpath, "train")
        test_dir = os.path.join(dirpath, "test")
        if validation:
            validation_input_path = os.path.join(train_dir, "attack_and_normal.csv")
            train_input_path = os.path.join(train_dir, "normal_only.csv")
        else:
            validation_input_path = None
            train_input_path = os.path.join(train_dir, "attack_and_normal.csv")
        test_input_path = os.path.join(test_dir, "attack_and_normal.csv")

        if not (os.path.exists(train_input_path) and os.path.exists(test_input_path)
                and (os.path.exists(validation_input_path) if validation else True)):
            continue

        parts = os.path.relpath(dirpath, root_dir).split(os.sep)
        if len(parts) >= 3:
            pg = {
                "dataset": parts[1],
                "goid": parts[2],
                "attack_type": parts[-1],
                "train_input_path": train_input_path,
                "test_input_path": test_input_path,
            }
            if validation:
                pg["validation_input_path"] = validation_input_path
            all_paths.append(pg)
    return all_paths


# ---------------------------------------------------------------------------
#  Run one algorithm over all datasets
# ---------------------------------------------------------------------------
def run_algorithm(algorithm, root_directory, validation=True):
    datasets = find_dataset_paths(root_directory, validation=validation)
    if not datasets:
        print("No datasets found. Check the directory structure.")
        return

    total = len(datasets)
    script_name = os.path.join(ALGORITHMS_DIR, f"{algorithm}.py")

    for i, ds in enumerate(datasets, start=1):
        try:
            print(f"[{algorithm}] {i}/{total}  "
                  f"{ds['dataset']} > {ds['goid']} > {ds['attack_type']}")

            output_dir = os.path.join(
                REPO_ROOT, "results_dir", ds["dataset"], ds["goid"], ds["attack_type"])
            os.makedirs(output_dir, exist_ok=True)

            cmd = [
                sys.executable, script_name,
                "--train_input_path", ds["train_input_path"],
                "--test_input_path", ds["test_input_path"],
                "--validation_input_path", str(ds.get("validation_input_path")),
                "--output_dir", output_dir,
                "--dataset", ds["dataset"],
                "--goid", ds["goid"],
                "--attack_type", ds["attack_type"],
            ]
            subprocess.run(cmd, check=True)
        except Exception as e:  # noqa: BLE001
            print(f"  ! error, skipping {ds['dataset']} > {ds['goid']} > "
                  f"{ds['attack_type']}: {e}")


def main(algorithms=None, root_directory=None, validation=True):
    warnings.filterwarnings("ignore")
    algorithms = algorithms or UNSUPERVISED
    root_directory = root_directory or DATA_ROOT

    if not os.path.isdir(root_directory):
        raise SystemExit(
            f"Dataset folder not found:\n    {root_directory}\n"
            f"Download the datasets from {DATA_URL} and extract them there."
        )

    for algorithm in algorithms:
        print("=" * 80)
        print(f"Running algorithm: {algorithm}")
        run_algorithm(algorithm, root_directory, validation=validation)


if __name__ == "__main__":
    main()
