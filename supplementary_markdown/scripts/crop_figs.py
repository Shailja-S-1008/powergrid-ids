"""Crop the supplementary figures out of the compiled PDF (vector -> PNG) using poppler's pdftoppm.
Usage: python3 crop_figs.py <supplementary.pdf> <out_dir>
Boxes are (page, x0, y0, x1, y1) in PDF points (612 x 792 page); caption text is excluded."""
import subprocess, sys, os
DPI = 220
FIGS = {
    "F1_dataset_heatmap_f1":        (5, 40, 34, 578, 219),
    "F2_window_size_sv":            (7, 40, 420, 305, 518),
    "F3_window_size_mms":           (7, 40, 548, 305, 650),
    "F4_dataset_size_goose_all":    (8, 40, 322, 578, 471),
    "F5_supervised_attack_heatmap": (20, 40, 31, 578, 332),
    "F6_supervised_size_goose":     (20, 40, 360, 302, 539),
    "F7_supervised_size_sv":        (20, 40, 562, 302, 727),
    "F8_supervised_size_mms":       (20, 304, 360, 578, 525),
    "F9_testbed_architecture":      (22, 40, 36, 578, 575),
}
def main(pdf, out):
    os.makedirs(out, exist_ok=True)
    s = DPI / 72.0
    for name, (p, x0, y0, x1, y1) in FIGS.items():
        base = os.path.join(out, name)
        subprocess.run(["pdftoppm", "-png", "-singlefile", "-r", str(DPI), "-f", str(p), "-l", str(p),
                        "-x", str(int(x0*s)), "-y", str(int(y0*s)),
                        "-W", str(int((x1-x0)*s)), "-H", str(int((y1-y0)*s)), pdf, base], check=True)
        print("wrote", base + ".png")
if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
