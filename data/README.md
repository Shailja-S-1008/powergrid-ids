# Datasets

The preprocessed datasets are **not** bundled with the code. Download them
separately and extract them here.

> **Download URL (placeholder):** `https://example.com/REPLACE_WITH_DATASET_URL`
>
> Replace this with the real hosted link and update `DATA_URL` in
> `pipeline/run_all.py`.

## Expected layout

`run_all.py` walks `data/preprocessed/` looking for any folder that contains
both a `train/` and a `test/` subfolder:

```
data/preprocessed/<group>/<dataset>/<goid>/<attack_type>/
    ├── train/
    │   ├── normal_only.csv          # training data (normal only)
    │   └── attack_and_normal.csv    # used as validation
    └── test/
        └── attack_and_normal.csv    # evaluation data
```

Each CSV has one row per packet: feature columns plus an `attack` label
column (0 = normal, 1 = attack).
