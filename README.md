# PowerGrid IDS — Anomaly-Detection Algorithm Suite

A benchmark harness that runs a suite of unsupervised anomaly-detection
algorithms over many power-grid intrusion-detection datasets. Each algorithm
trains and evaluates per dataset case and records its metrics and resource
usage to a per-algorithm CSV.

## Layout

```
.
├── pipeline/
│   └── run_all.py            # entry point: runs every algorithm over all datasets
├── algorithms/               # one runnable script per algorithm (30)
│   ├── iqr.py  iqr_mom.py  z_score.py          # statistical
│   ├── pam.py  clara.py  optics.py  singleLink.py  ward.py
│   │   spectral_clustering.py  kmeans.py  gmm.py  hbos.py   # clustering / density
│   ├── pca.py  vae.py  ae.py                    # reconstruction
│   ├── lof.py  If.py  ocsvm.py  svdd.py         # anomaly detection
│   
├── utility/
│   ├── unsupervised_helper.py  # data loading, feature selection, result CSV writers
│   ├── resource_usage.py       # CPU / RAM / time profiler
│   └── plot_helper.py          # path-hierarchy helper
├── data/                       # datasets, downloaded separately — see data/README.md
├── requirements.txt
└── README.md
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# For the deep-learning algorithms also install torch and/or tensorflow
# (see the commented lines in requirements.txt).
```

## Get the data

Datasets are hosted separately. Download and extract them into
`data/preprocessed/` (see [`data/README.md`](data/README.md)) and set the real
link in `DATA_URL` (`pipeline/run_all.py`).


## Run

```bash
python pipeline/run_all.py                 # runs the unsupervised set by default
```

Each algorithm can also be run directly on one dataset case:

```bash
python algorithms/iqr.py \
    --train_input_path  data/preprocessed/.../train/normal_only.csv \
    --test_input_path   data/preprocessed/.../test/attack_and_normal.csv \
    --validation_input_path data/preprocessed/.../train/attack_and_normal.csv \
    --output_dir results_dir/<dataset>/<goid>/<attack> \
    --dataset <dataset> --goid <goid> --attack_type <attack>
```

### Outputs

Per-algorithm metrics are written to `outputs/Algorithm_wise_plots_data/<algo>_metrics_long.csv`
(override the base folder with the `PG_OUTPUT_DIR` environment variable). Run
logs go to `outputs/logs/`.

### Which algorithms run

`run_all.py` runs the `UNSUPERVISED` list by default; the `SUPERVISED` list is
defined alongside it and can be swapped in. Edit the ranking metric via
`col_name` in `utility/unsupervised_helper.py` (default: `MCC`).
