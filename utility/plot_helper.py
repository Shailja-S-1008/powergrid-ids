"""Small path helper shared by the algorithm scripts.

Only ``infer_hierarchy_from_output_dir`` is used by the pipeline: given an
output directory such as ``results_dir/<dataset>/<goid>/<attack>`` it returns
the ``(dataset, goid, attack)`` triple encoded in the trailing path segments.
"""
import os


def infer_hierarchy_from_output_dir(output_dir):
    """Return ``(dataset, goid, attack)`` from the last three path segments.

    Missing segments come back as ``"all"`` so callers always get a 3-tuple.
    """
    parts = [p for p in os.path.normpath(output_dir or "").split(os.sep) if p]
    dataset, goid, attack = "all", "all", "all"
    if len(parts) >= 3:
        dataset, goid, attack = parts[-3], parts[-2], parts[-1]
    elif len(parts) == 2:
        dataset, goid = parts[-2], parts[-1]
    elif len(parts) == 1:
        dataset = parts[-1]
    return dataset, goid, attack
