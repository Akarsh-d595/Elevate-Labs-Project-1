#!/usr/bin/env python3
"""
Password Strength Analyzer & Custom Wordlist Generator

Features
- CLI (argparse) and optional Tkinter GUI.
- Uses zxcvbn (if installed) for password scoring; falls back to a simple entropy estimator.
- Generates wordlist candidates from user-supplied tokens (names, dates, pets, etc.).
- Includes leetspeak substitutions, case variants, year suffixes, pairwise combinations,
  and common suffixes. Exports to a .txt file for use with cracking or audit tools.

Notes
- This tool is for defensive/security awareness and educational use only.
- Do not use against systems or accounts you don't own/authorize.
"""

from __future__ import annotations
import argparse
import itertools
from datetime import datetime
import sys
from typing import List, Set, Dict

# Optional dependency: zxcvbn for richer password scoring
try:
    from zxcvbn import zxcvbn  # pip package name: zxcvbn
except Exception:
    zxcvbn = None

# Optional: NLTK may be used later for token normalization (not required at runtime)
try:
    import nltk  # pip package name: nltk
except Exception:
    nltk = None

# --------------------------
# Password analysis section
# --------------------------

def analyze_password(password: str) -> Dict:
    """
    Analyze password strength.
    Returns a dict with keys: score (0-4 or None), entropy (float), feedback (dict or text).
    If zxcvbn is available, its output is returned (trimmed). Otherwise a fallback estimate used.
    """
    if not password:
        return {"score": None, "entropy": 0.0, "feedback": "No password provided."}

    if zxcvbn:
        try:
            res = zxcvbn(password)
            return {
                "score": res.get("score"),
                "entropy": res.get("entropy"),
                "feedback": res.get("feedback", {}),
                "crack_times_display": res.get("crack_times_display", {}),
            }
        except Exception:
            # If zxcvbn fails for any reason, fall through to fallback estimator
            pass

    # Fallback entropy estimate (crude)
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32  # rough estimate for symbol set

    # Use log2(pool) * length approx -> bits; but use bit_length() of pool for simplicity
    bits_per_char = pool.bit_length() if pool else 0
    entropy = len(password) * bits_per_char
    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 90:
        score = 3
    else:
        score = 4

    return {"score": score, "entropy": entropy, "feedback": {"warning": "Fallback estimator used."}}

# --------------------------
# Wordlist generation logic
# --------------------------

# Controlled leet mapping to avoid combinatorial explosion
LEET_MAP = {
    "a": ["@", "4"],
    "b": ["8"],
    "e": ["3"],
    "i": ["1", "!"],
    "l": ["1", "|"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
}

def leet_variations(token: str, max_subs: int = 2) -> Set[str]:
    """
    Generate leetspeak variants for a token.
    max_subs: limit number of positions substituted at once to control explosion.
    Returns a set including the original token.
    """
    token = token.strip()
    if not token:
        return set()

    variants = {token}
    lower = token.lower()
    positions = [i for i, ch in enumerate(lower) if ch in LEET_MAP]

    # Generate combinations of substitution positions (1..max_subs)
    for r in range(1, min(max_subs, len(positions)) + 1):
        for comb in itertools.combinations(positions, r):
            # Build iterative substitution sequences to try all mapped chars per position
            seqs = [list(token)]
            for pos in comb:
                new_seqs = []
                for seq in seqs:
                    ch = seq[pos].lower()
                    subs = LEET_MAP.get(ch, [])
                    for s in subs:
                        new_seq = seq.copy()
                        new_seq[pos] = s
                        new_seqs.append(new_seq)
                if new_seqs:
                    seqs = new_seqs
            for seq in seqs:
                variants.add("".join(seq))

    return variants

def append_recent_years(token: str, years_back: int = 10) -> Set[str]:
    """
    Append recent years to a token (last `years_back` years, inclusive of current year).
    Example: if current year is 2025 and years_back=3 -> token2023..token2025
    """
    token = token.strip()
    if not token:
        return set()
    current = datetime.now().year
    years = {str(y) for y in range(current - years_back + 1, current + 1)}
    return {token + y for y in years}

def generate_wordlist(tokens: List[str],
                      max_words: int = 50000,
                      append_years_flag: bool = True,
                      include_common_suffixes: bool = True) -> List[str]:
    """
    Generate a deterministic sorted list of candidate words based on tokens.
    - tokens: list of user-provided tokens (names, pets, dates, etc.)
    - max_words: cap to avoid huge outputs
    """
    clean_tokens = [t.strip() for t in tokens if t and t.strip()]
    results: Set[str] = set()

    # Basic case variants + leet + years
    for t in clean_tokens:
        results.add(t)
        results.add(t.lower())
        results.add(t.upper())
        results.add(t.capitalize())

        # Leet variants
        for v in leet_variations(t):
            results.add(v)
            results.add(v.lower())

        # Append years
        if append_years_flag:
            for v in append_recent_years(t):
                results.add(v)
                results.add(v.lower())

    # Pairwise combinations (order matters: permutations)
    for a, b in itertools.permutations(clean_tokens, 2):
        results.add(a + b)
        results.add(a + "_" + b)

    # Add common suffixes to snapshot (avoid iterating over growing set)
    if include_common_suffixes:
        common_suffixes = ["123", "!", "@", "2020", "2021", "2022"]
        snapshot = list(results)  # snapshot to extend from
        for base in snapshot:
            for s in common_suffixes:
                results.add(base + s)

    # Limit size deterministically
    if len(results) > max_words:
        results = set(sorted(results)[:max_words])

    return sorted(results)

# --------------------------
# CLI + GUI launcher
# --------------------------

def cli_main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer & Custom Wordlist Generator")
    parser.add_argument("--password", "-p", help="Password to analyze (optional).")
    parser.add_argument("--inputs", "-i", help="Comma-separated tokens (example: 'Alice,Fluffy,1990')", default="")
    parser.add_argument("--output", "-o", help="Output wordlist file (default: custom_wordlist.txt)", default="custom_wordlist.txt")
    parser.add_argument("--no-years", dest="years", action="store_false", help="Do not append recent years to tokens.")
    parser.add_argument("--max-words", type=int, default=50000, help="Maximum number of candidate words to generate.")
    parser.add_argument("--gui", action="store_true", help="Launch the optional Tkinter GUI.")
    args = parser.parse_args()

    if args.gui:
        launch_gui()
        return

    tokens = [t.strip() for t in args.inputs.split(",") if t.strip()]

    # Analyze password if provided
    if args.password:
        info = analyze_password(args.password)
        print("Password analysis:")
        print(f"  Score (0-4): {info.get('score')}")
        print(f"  Entropy: {info.get('entropy')}")
        feedback = info.get('feedback')
        if feedback:
            print("  Feedback:")
            if isinstance(feedback, dict):
                for k, v in feedback.items():
                    print(f"    - {k}: {v}")
            else:
                print(f"    - {feedback}")
        print()

    if not tokens:
        print("No input tokens provided. Use --inputs 'Alice,Fluffy,1990' to provide tokens for generation.")
        return

    wordlist = generate_wordlist(tokens, max_words=args.max_words, append_years_flag=args.years)
    with open(args.output, "w", encoding="utf-8") as fh:
        for w in wordlist:
            fh.write(w + "\n")

    print(f"Generated {len(wordlist)} words and saved to: {args.output}")

# --------------------------
# Optional Tkinter GUI
# --------------------------

def launch_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, filedialog
    except Exception:
        print("Tkinter is not available on this system.")
        return

    root = tk.Tk()
    root.title("Password Analyzer & Wordlist Generator")

    frm = ttk.Frame(root, padding=12)
    frm.grid(sticky="nsew")

    ttk.Label(frm, text="Password (optional):").grid(column=0, row=0, sticky="w")
    pw_entry = ttk.Entry(frm, width=45)
    pw_entry.grid(column=1, row=0, sticky="w")

    ttk.Label(frm, text="Tokens (comma-separated):").grid(column=0, row=1, sticky="w")
    in_entry = ttk.Entry(frm, width=45)
    in_entry.grid(column=1, row=1, sticky="w")

    ttk.Label(frm, text="Output file:").grid(column=0, row=2, sticky="w")
    out_entry = ttk.Entry(frm, width=45)
    out_entry.insert(0, "custom_wordlist.txt")
    out_entry.grid(column=1, row=2, sticky="w")

    def on_generate():
        pw = pw_entry.get().strip()
        tokens = [t.strip() for t in in_entry.get().split(",") if t.strip()]
        out = out_entry.get().strip() or "custom_wordlist.txt"
        if pw:
            info = analyze_password(pw)
            messagebox.showinfo("Password Analysis", f"Score: {info.get('score')}\nEntropy: {info.get('entropy')}")
        if not tokens:
            messagebox.showwarning("No tokens", "Please provide at least one token to generate the wordlist.")
            return
        wl = generate_wordlist(tokens)
        try:
            with open(out, "w", encoding="utf-8") as fh:
                for w in wl:
                    fh.write(w + "\n")
            messagebox.showinfo("Done", f"Saved {len(wl)} words to {out}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    gen_btn = ttk.Button(frm, text="Generate Wordlist", command=on_generate)
    gen_btn.grid(column=1, row=3, pady=8, sticky="e")

    root.mainloop()

# --------------------------
# Entry point
# --------------------------

if __name__ == "__main__":
    cli_main()
