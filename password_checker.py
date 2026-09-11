#!/usr/bin/env python3
"""
=====================================================================
 Password Strength Checker + Breach Detector
 Author: <Your Name>

 Features:
   1. Analyzes password strength (length, character variety, entropy,
      common patterns/dictionary words)
   2. Checks the password against the Have I Been Pwned (HIBP) breach
      database using the k-anonymity model (only the first 5 chars of
      the SHA-1 hash are sent over the network — your real password
      NEVER leaves your machine, and not even the full hash does)

 Usage:
   python password_checker.py
   python password_checker.py --password "MySecret123!"
   python password_checker.py --no-breach-check   (skip API call, offline only)
=====================================================================
"""

import re
import sys
import math
import hashlib
import argparse
import getpass

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ---------------------------------------------------------------
# COMMON WEAK PASSWORDS (small sample — extend this list as needed)
# ---------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "12345678", "letmein", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "football", "1234567", "123123", "qwerty123",
    "sunshine", "master", "trustno1"
}


# ---------------------------------------------------------------
# STRENGTH ANALYSIS
# ---------------------------------------------------------------
def calculate_entropy(password: str) -> float:
    """Estimate password entropy in bits based on character pool size."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # approx count of common special characters

    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def analyze_strength(password: str) -> dict:
    """Return a dict with score, rating, and specific feedback."""
    feedback = []
    score = 0

    length = len(password)

    # --- Length ---
    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("Password too short — use at least 12 characters.")

    # --- Character variety ---
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety_count = sum([has_lower, has_upper, has_digit, has_special])
    score += variety_count

    if not has_lower:
        feedback.append("Add lowercase letters.")
    if not has_upper:
        feedback.append("Add uppercase letters.")
    if not has_digit:
        feedback.append("Add numbers.")
    if not has_special:
        feedback.append("Add special characters (!@#$%^&* etc).")

    # --- Common password check ---
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("This is a widely used common password — change it immediately.")

    # --- Sequential / repeated pattern check ---
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        feedback.append("Avoid repeating the same character 3+ times in a row.")

    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwerty)", password.lower()):
        score -= 1
        feedback.append("Avoid common sequential patterns (1234, abcd, qwerty).")

    entropy = calculate_entropy(password)

    # --- Final rating ---
    score = max(0, score)
    if score <= 2:
        rating = "Very Weak"
    elif score <= 4:
        rating = "Weak"
    elif score <= 6:
        rating = "Medium"
    elif score <= 7:
        rating = "Strong"
    else:
        rating = "Very Strong"

    if not feedback:
        feedback.append("Good password hygiene — no major issues found.")

    return {
        "length": length,
        "entropy_bits": round(entropy, 1),
        "score": score,
        "rating": rating,
        "feedback": feedback,
    }


# ---------------------------------------------------------------
# HIBP BREACH CHECK (k-anonymity model)
# ---------------------------------------------------------------
def check_breach(password: str) -> dict:
    """
    Queries the Have I Been Pwned API using the k-anonymity model.
    Only the first 5 characters of the SHA-1 hash are sent to the API —
    the full password and full hash never leave this machine.
    """
    if not REQUESTS_AVAILABLE:
        return {"error": "The 'requests' library is not installed. Run: pip install requests"}

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": "PasswordCheckerProject"})
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {"error": f"Could not reach HIBP API: {e}"}

    hashes = (line.split(":") for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return {"breached": True, "count": int(count)}

    return {"breached": False, "count": 0}


# ---------------------------------------------------------------
# DISPLAY HELPERS
# ---------------------------------------------------------------
def print_bar(score: int, max_score: int = 8):
    filled = int((score / max_score) * 20)
    bar = "#" * filled + "-" * (20 - filled)
    print(f"[{bar}] {score}/{max_score}")


def print_report(password: str, strength: dict, breach: dict = None):
    print("\n" + "=" * 55)
    print(" PASSWORD SECURITY REPORT")
    print("=" * 55)
    print(f"Password length : {strength['length']} characters")
    print(f"Estimated entropy: {strength['entropy_bits']} bits")
    print(f"Strength rating  : {strength['rating']}")
    print_bar(strength["score"])
    print("\nFeedback:")
    for item in strength["feedback"]:
        print(f"  - {item}")

    if breach is not None:
        print("\n" + "-" * 55)
        print(" BREACH CHECK (Have I Been Pwned)")
        print("-" * 55)
        if "error" in breach:
            print(f"  Could not complete breach check: {breach['error']}")
        elif breach["breached"]:
            print(f"  ⚠ This password has appeared in {breach['count']:,} known data breaches!")
            print("  Recommendation: Do NOT use this password. Change it immediately wherever used.")
        else:
            print("  ✓ Good news — this password was not found in any known breach.")
    print("=" * 55 + "\n")


# ---------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker + Breach Detector")
    parser.add_argument("--password", type=str, help="Password to check (omit to be prompted securely)")
    parser.add_argument("--no-breach-check", action="store_true", help="Skip the online HIBP breach check")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter password to check (input hidden): ")

    if not password:
        print("No password entered. Exiting.")
        sys.exit(1)

    strength = analyze_strength(password)

    breach = None
    if not args.no_breach_check:
        print("\nChecking against Have I Been Pwned database...")
        breach = check_breach(password)

    print_report(password, strength, breach)


if __name__ == "__main__":
    main()
