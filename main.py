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
    if any(c.isdigit()
