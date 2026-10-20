#!/usr/bin/env python3
"""Convert the IQR-MOM supplementary LaTeX file into GitHub-flavoured Markdown.

Usage:
    python3 tex2md.py Supplementry_latest.tex supplementary.pdf out_dir

* Prose, sections, lists, and all tables are converted from the .tex source.
* Figures are referenced as PNGs in out_dir/figures (create them with crop_figs.py).
* The numbered reference list is taken from the compiled PDF (needs poppler's pdftotext).
* Rank highlighting follows the PDF legend: 1st = bold + underline, 2nd = bold, 3rd = underline.
"""
import os
import re
import subprocess
import sys

# ----------------------------------------------------------------------------
# Figure images produced by crop_figs.py, in figure-number order (F1, F2, ...)
FIGURE_FILES = [
    "F1_dataset_heatmap_f1.png",
    "F2_window_size_sv.png",
    "F3_window_size_mms.png",
    "F4_dataset_size_goose_all.png",
    "F5_supervised_attack_heatmap.png",
    "F6_supervised_size_goose.png",
    "F7_supervised_size_sv.png",
    "F8_supervised_size_mms.png",
    "F9_testbed_architecture.png",
]

TITLE = ("Lightweight Unsupervised Anomaly Detection for IEC 61850 Digital Substations: "
         "Multi-Protocol Benchmarking and Edge Deployment")
AUTHORS = ("Shailja Sharma, Kunal A. Wasnik, V Srimugdha Mahalakshmi, Anushtha Tamrakar, Rayaan Ghosh, "
           "Prasanna Mathavan J.T, Harshavardhan P V, Charan Teja, Vishwajeet Pattanaik, Punit Rathore, "
           "Gurunath Gurrala, Akhil Sundaran, Saumya Singh, and Kiran T S")

ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII", "XIII", "XIV", "XV"]


# ----------------------------------------------------------------------------
# Low-level helpers
def strip_comments(s):
    out = []
    for line in s.split("\n"):
        m = re.search(r"(?<!\\)%", line)
        out.append(line[:m.start()] if m else line)
    return "\n".join(out)


def match_brace(s, i):
    """s[i] == '{' -> index of the matching '}'."""
    depth = 0
    j = i
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    raise ValueError("unbalanced braces near: " + s[i:i + 80])


def read_args(s, i, n, optional=True):
    """Read an optional [..] and n {..} groups starting at s[i]. Returns (args, new_i)."""
    while i < len(s) and s[i] in " \t\n":
        i += 1
    if optional and i < len(s) and s[i] == "[":
        i = s.index("]", i) + 1
    args = []
    for _ in range(n):
        while i < len(s) and s[i] in " \t\n":
            i += 1
        if i < len(s) and s[i] == "{":
            j = match_brace(s, i)
            args.append(s[i + 1:j])
            i = j + 1
        else:  # single-token argument, e.g. \multirow{2}{*}X
            args.append(s[i] if i < len(s) else "")
            i += 1
    return args, i


def anchor(label_text):
    return re.sub(r"[^a-z0-9]+", "-", label_text.lower()).strip("-")


# ----------------------------------------------------------------------------
class Converter:
    def __init__(self, tex, refs):
        self.tex = tex
        self.refs = refs              # list of reference strings from the PDF
        self.labels = {}              # label -> (display text, anchor)
        self.cite_num = {}            # key -> number
        self.fig_no = 0
        self.tab_no = 0

    # ---------------- numbering pre-pass ----------------
    def number(self, body):
        sec = sub = subsub = tab = fig = 0
        ctx = None
        tok = re.compile(r"\\(section|subsection|subsubsection)\*?\{|\\begin\{(table\*?|figure\*?)\}"
                         r"|\\end\{(table\*?|figure\*?)\}|\\label\{([^}]*)\}|\\cite\{([^}]*)\}")
        for m in tok.finditer(body):
            if m.group(1) == "section":
                sec += 1; sub = subsub = 0
                ctx = ("S-" + ROMAN[sec - 1], "s-" + ROMAN[sec - 1].lower())
            elif m.group(1) == "subsection":
                sub += 1; subsub = 0
                ctx = ("S-%s-%s" % (ROMAN[sec - 1], chr(64 + sub)), None)
            elif m.group(1) == "subsubsection":
                subsub += 1
            elif m.group(2):
                if m.group(2).startswith("table"):
                    tab += 1; ctx = ("T%d" % tab, "t%d" % tab)
                else:
                    fig += 1; ctx = ("F%d" % fig, "f%d" % fig)
            elif m.group(3):
                ctx = ("S-" + ROMAN[sec - 1], "s-" + ROMAN[sec - 1].lower()) if sec else None
            elif m.group(4) and ctx:
                self.labels[m.group(4)] = ctx
            elif m.group(5):
                for k in m.group(5).split(","):
                    k = k.strip()
                    if k and k not in self.cite_num:
                        self.cite_num[k] = len(self.cite_num) + 1

    # ---------------- inline conversion ----------------
    def inline(self, s, in_table=False):
        out = []
        i = 0
        n = len(s)
        while i < n:
            c = s[i]
            if c == "$":
                j = i + 1
                while j < n and not (s[j] == "$" and s[j - 1] != "\\"):
                    j += 1
                math = s[i + 1:j].strip()
                if re.fullmatch(r"[A-Za-z]{2,}", math):        # field names such as $gocbRef$
                    out.append("*" + math + "*")
                elif re.fullmatch(r"[0-9.]+", math):           # plain numbers such as $5$
                    out.append(math)
                else:
                    out.append("$" + math + "$")
                i = j + 1
                continue
            if c == "\\":
                if i + 1 < n and not s[i + 1].isalpha():
                    ch = s[i + 1]
                    if ch == "\\":                      # \\ (optionally \\[..])
                        i += 2
                        if i < n and s[i] == "[":
                            i = s.index("]", i) + 1
                        out.append(" ")
                        continue
                    out.append({",": " ", " ": " ", ";": " ", "!": ""}.get(ch, ch))
                    i += 2
                    continue
                m = re.match(r"\\([A-Za-z]+)\*?", s[i:])
                name = m.group(1)
                i += m.end()
                text, i = self.command(name, s, i, in_table)
                out.append(text)
                continue
            if c in "{}":
                i += 1
                continue
            if c == "~":
                out.append(" ")
                i += 1
                continue
            if s.startswith("``", i):
                out.append("\u201c"); i += 2; continue
            if s.startswith("''", i):
                out.append("\u201d"); i += 2; continue
            if s.startswith("---", i):
                out.append("\u2014"); i += 3; continue
            if s.startswith("--", i):
                out.append("\u2013"); i += 2; continue
            if in_table and c == "|":
                out.append("\\|"); i += 1; continue
            out.append(c)
            i += 1
        text = "".join(out)
        return re.sub(r"[ \t]+", " ", text)

    def command(self, name, s, i, in_table):
        """Return (markdown, new_index) for \\name whose arguments start at s[i]."""
        fmt1 = {
            "textbf": "**{}**", "textit": "*{}*", "emph": "*{}*", "texttt": "`{}`",
            "underline": "<ins>{}</ins>", "best": "**<ins>{}</ins>**", "second": "**{}**",
            "third": "<ins>{}</ins>", "cl": "{}", "centerline": "{}", "mbox": "{}",
            "textsubscript": "<sub>{}</sub>", "textsuperscript": "<sup>{}</sup>",
        }
        drop = {"vspace": 1, "hspace": 1, "setlength": 2, "renewcommand": 2, "label": 1,
                "colorbox": 2, "cellcolor": 1, "rowcolor": 1, "cline": 1, "clnote": 1,
                "extracolsep": 1, "definecolor": 3}
        zero = {"centering", "footnotesize", "scriptsize", "small", "noindent", "strut", "hfill",
                "FloatBarrier", "clearpage", "justifying", "par", "hline", "toprule", "midrule",
                "bottomrule", "raggedright", "arraybackslash", "maketitle", "linewidth", "textwidth",
                "columnwidth", "arraystretch", "tabcolsep", "baselineskip", "newline"}
        symbols = {"ldots": "\u2026", "textbackslash": "\\", "times": "\u00d7", "approx": "\u2248",
                   "sim": "~", "leq": "\u2264", "geq": "\u2265", "textendash": "\u2013",
                   "textemdash": "\u2014", "LaTeX": "LaTeX"}
        if name in fmt1:
            args, j = read_args(s, i, 1, optional=False)
            inner = self.inline(args[0], in_table).strip()
            return (fmt1[name].format(inner) if inner else ""), j
        if name in drop:
            args, j = read_args(s, i, drop[name], optional=(name != "renewcommand"))
            return (""), j
        if name in zero:
            return (""), i
        if name in symbols:
            return (symbols[name]), i
        if name == "ref":
            args, j = read_args(s, i, 1, optional=False)
            key = args[0].strip()
            if key in self.labels:
                text, anc = self.labels[key]
                return ("[%s](#%s)" % (text, anc) if anc else text), j
            return "??", j
        if name == "cite":
            args, j = read_args(s, i, 1, optional=False)
            nums = [self.cite_num[k.strip()] for k in args[0].split(",") if k.strip() in self.cite_num]
            return ("[" + ", ".join("[%d](#ref-%d)" % (k, k) for k in nums) + "]"), j
        if name == "multirow":
            args, j = read_args(s, i, 3, optional=False)
            return (self.inline(args[2], in_table)), j
        if name == "multicolumn":
            args, j = read_args(s, i, 3, optional=False)
            return ("\x00MC%s\x00%s" % (args[0], self.inline(args[2], in_table))), j
        if name == "resizebox":
            args, j = read_args(s, i, 3, optional=False)
            return (self.inline(args[2], in_table)), j
        # unknown command: drop the name, keep (converted) braces that follow
        return (""), i

    # ---------------- tables ----------------
    def tabular_to_md(self, body):
        body = re.sub(r"\\(hline|toprule|midrule|bottomrule)", "", body)
        body = re.sub(r"\\cline\{[^}]*\}", "", body)
        rows = re.split(r"\\\\(?:\[[^\]]*\])?", body)
        table = []
        for r in rows:
            if not r.strip():
                continue
            cells = re.split(r"(?<!\\)&", r)
            out = []
            for c in cells:
                txt = self.inline(c, in_table=True).strip()
                m = re.match(r"\x00MC(\d+)\x00(.*)", txt, re.S)
                if m:
                    out.append(m.group(2).strip())
                    out.extend([m.group(2).strip()] * (int(m.group(1)) - 1))
                else:
                    out.append(txt)
            if any(x for x in out):
                table.append(out)
        if not table:
            return ""
        # two-row header with \multicolumn spans (dataset-size table): merge into one header row
        header = table[0]
        start = 1
        raw_first = rows[0] if rows else ""
        if "multicolumn" in body.split("\\\\")[0] and len(table) > 1:
            sub = table[1]
            header = ["**%s**" % " ".join(x.replace("**", "") for x in (h, s_) if x).strip() for h, s_ in
                      zip(header + [""] * (len(sub) - len(header)), sub)]
            start = 2
        width = max(len(r) for r in table)
        header = header + [""] * (width - len(header))
        lines = ["| " + " | ".join(h if h else " " for h in header) + " |",
                 "|" + "|".join(["---"] * width) + "|"]
        for r in table[start:]:
            r = r + [""] * (width - len(r))
            lines.append("| " + " | ".join(r) + " |")
        return "\n".join(lines)

    def table_env(self, env_body):
        cap, _ = self._caption(env_body)
        self.tab_no += 1
        num = "T%d" % self.tab_no
        parts = []
        tab_re = re.compile(r"\\begin\{(tabularx|tabular\*|tabular)\}")
        pos = 0
        md_tables = []
        notes = []
        for m in tab_re.finditer(env_body):
            if m.start() < pos:
                continue
            env = m.group(1)
            nargs = 2 if env in ("tabularx", "tabular*") else 1
            _, k = read_args(env_body, m.end(), nargs, optional=False)
            end = env_body.index("\\end{%s}" % env, k)
            md_tables.append(self.tabular_to_md(env_body[k:end]))
            pos = end + len("\\end{%s}" % env)
            notes.append(env_body[pos:])
        tail = notes[-1] if notes else ""
        tail = re.sub(r"\\end\{(minipage|flushleft)\}|\\begin\{(minipage|flushleft)\}(\{[^}]*\})?", "", tail)
        tail = re.sub(r"^\s*\}", "", tail)  # closing brace of \resizebox{..}{..}{tabular}
        note = " ".join(self.inline(tail).split())
        note = re.sub(r"\s+([,.])", r"\1", note)
        parts.append('<a id="%s"></a>\n\n**Table %s. %s**' % (num.lower(), num, cap))
        parts.extend(md_tables)
        if note:
            parts.append(note)
        return "\n\n".join(parts)

    def figure_env(self, env_body):
        cap, _ = self._caption(env_body)
        self.fig_no += 1
        num = "F%d" % self.fig_no
        img = FIGURE_FILES[self.fig_no - 1] if self.fig_no <= len(FIGURE_FILES) else ""
        return ('<a id="%s"></a>\n\n![Fig. %s](figures/%s)\n\n**Fig. %s.** %s'
                % (num.lower(), num, img, num, cap))

    def _caption(self, env_body):
        k = env_body.find("\\caption")
        if k < 0:
            return "", None
        args, j = read_args(env_body, k + len("\\caption"), 1)
        return self.inline(args[0]).strip(), j

    def list_env(self, body, ordered):
        items = re.split(r"\\item\s*", body)[1:]
        lines = []
        for n, it in enumerate(items, 1):
            bullet = "%d." % n if ordered else "-"
            lines.append("%s %s" % (bullet, self.inline(" ".join(it.split())).strip()))
        return "\n".join(lines)

    # ---------------- text / headings ----------------
    def text_block(self, s):
        out = []
        head = re.compile(r"\\(section|subsection|subsubsection)\*?\s*\{")
        sec = getattr(self, "_sec", 0)
        sub = getattr(self, "_sub", 0)
        subsub = getattr(self, "_subsub", 0)
        pos = 0
        pieces = []
        for m in head.finditer(s):
            pieces.append(("text", s[pos:m.start()]))
            j = match_brace(s, m.end() - 1)
            pieces.append((m.group(1), s[m.end():j]))
            pos = j + 1
        pieces.append(("text", s[pos:]))
        for kind, val in pieces:
            if kind == "text":
                for para in re.split(r"\n\s*\n", val):
                    t = self.inline(" ".join(para.split())).strip()
                    t = re.sub(r"\s+([,.;:)])", r"\1", t)
                    if t:
                        out.append(t)
            elif kind == "section":
                sec += 1; sub = subsub = 0
                r = ROMAN[sec - 1]
                out.append('<a id="s-%s"></a>\n\n## S-%s. %s' % (r.lower(), r, self.inline(val).strip()))
            elif kind == "subsection":
                sub += 1; subsub = 0
                out.append("### %s. %s" % (chr(64 + sub), self.inline(val).strip()))
            else:
                subsub += 1
                out.append("#### %d) %s" % (subsub, self.inline(val).strip()))
        self._sec, self._sub, self._subsub = sec, sub, subsub
        return out

    # ---------------- driver ----------------
    def convert(self):
        tex = strip_comments(self.tex)
        body = tex[tex.index("\\begin{document}") + len("\\begin{document}"):tex.index("\\end{document}")]
        body = re.sub(r"\\bibliographystyle\{[^}]*\}|\\bibliography\{[^}]*\}|\\maketitle", "", body)
        self.number(body)
        out = ["# Supplementary Material", "## " + TITLE, "*" + AUTHORS + "*"]
        env_re = re.compile(r"\\begin\{(table\*?|figure\*?|itemize|enumerate)\}")
        pos = 0
        while True:
            m = env_re.search(body, pos)
            if not m:
                out.extend(self.text_block(body[pos:]))
                break
            out.extend(self.text_block(body[pos:m.start()]))
            env = m.group(1)
            end_tag = "\\end{%s}" % env
            end = body.index(end_tag, m.end())
            inner = body[m.end():end]
            inner = re.sub(r"^\s*\[[^\]]*\]", "", inner)
            if env.startswith("table"):
                out.append(self.table_env(inner))
            elif env.startswith("figure"):
                out.append(self.figure_env(inner))
            else:
                out.append(self.list_env(inner, env == "enumerate"))
            pos = end + len(end_tag)
        if self.refs:
            out.append('<a id="references"></a>\n\n## References')
            out.append("\n".join('<a id="ref-%d"></a>[%d] %s  ' % (k, k, r) for k, r in enumerate(self.refs, 1)))
        toc = ["**Contents**", ""]
        for x in out:
            m = re.search(r'<a id="(s-[ivx]+)"></a>\s*## (S-[IVX]+\. .*)', x)
            if m:
                toc.append("- [%s](#%s)" % (m.group(2), m.group(1)))
        if self.refs:
            toc.append("- [References](#references)")
        out.insert(3, "\n".join(toc))
        md = "\n\n".join(x for x in out if x.strip())
        md = re.sub(r"\n{3,}", "\n\n", md)
        return md + "\n"


# ----------------------------------------------------------------------------
def pdf_references(pdf):
    """Return the numbered reference list from the compiled PDF."""
    txt = subprocess.run(["pdftotext", pdf, "-"], capture_output=True, text=True, check=True).stdout
    k = txt.find("R EFERENCES")
    if k < 0:
        k = txt.find("REFERENCES")
    if k < 0:
        return []
    txt = re.sub(r"-\n(?=[a-z])", "", txt[k:])
    txt = re.sub(r"\n(?!\[\d+\])", " ", txt)
    refs = re.findall(r"^\[(\d+)\]\s*(.*)$", txt, re.M)
    out = []
    for _, r in refs:
        r = re.sub(r"\s+", " ", r).strip()
        r = re.sub(r"\s+\d{1,2}$", "", r)          # trailing page number
        r = re.sub(r"\s(2[0-9])\s(?=[a-z])", " ", r)   # page number caught inside an entry
        for _ in range(3):                             # URLs broken across lines
            r = re.sub(r"(https?://\S*/)\s+(?=[A-Za-z_])", r"\1", r)
        r = r.replace("en/latest/modules/pyod/", "en/latest/_modules/pyod/")  # '_' lost in PDF text
        out.append(r)
    return out


def main(tex_path, pdf_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    tex = open(tex_path, encoding="utf-8").read()
    refs = pdf_references(pdf_path) if pdf_path else []
    md = Converter(tex, refs).convert()
    path = os.path.join(out_dir, "Supplementary.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print("wrote", path, "(%d references)" % len(refs))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None, sys.argv[3] if len(sys.argv) > 3 else ".")
