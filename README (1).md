# Password Strength Checker + Breach Detector (Python)

A command-line tool that analyzes password strength offline and checks
whether a password has appeared in known data breaches — using the
**Have I Been Pwned (HIBP)** API with a privacy-safe **k-anonymity** model
(your real password, and even the full hash, never leaves your machine).

## What this project demonstrates
- Understanding of password security principles (entropy, complexity, common patterns)
- Practical use of hashing (SHA-1) and API integration
- Privacy-conscious design (k-anonymity model — a real technique used by HIBP itself)
- Clean CLI tool development in Python

## How the breach check works (important for interviews!)
1. Your password is hashed locally using SHA-1 — it is never sent anywhere.
2. Only the **first 5 characters** of that hash are sent to the HIBP API.
3. The API returns all hash suffixes that start with those 5 characters
   (usually several hundred).
4. Your script compares the *rest* of your hash against that list locally.
5. This means the API never sees your full password OR your full hash —
   this is called the **k-anonymity model**.

## Setup

```bash
pip install requests
```

## Usage

**Interactive (recommended — hides your typing):**
```bash
python password_checker.py
```

**Pass password directly (careful — visible in terminal history):**
```bash
python password_checker.py --password "MySecret123!"
```

**Offline mode only (skip the breach check, no internet needed):**
```bash
python password_checker.py --password "MySecret123!" --no-breach-check
```

## Sample Output

```
=======================================================
 PASSWORD SECURITY REPORT
=======================================================
Password length : 16 characters
Estimated entropy: 104.9 bits
Strength rating  : Strong
[#################---] 7/8

Feedback:
  - Good password hygiene — no major issues found.

-------------------------------------------------------
 BREACH CHECK (Have I Been Pwned)
-------------------------------------------------------
  ✓ Good news — this password was not found in any known breach.
=======================================================
```

## What the strength checker evaluates
- Length (12+ recommended, 16+ ideal)
- Character variety (uppercase, lowercase, digits, special characters)
- Estimated entropy (bits of randomness)
- Common password list matching
- Repeated character patterns (`aaa`, `111`)
- Sequential patterns (`1234`, `abcd`, `qwerty`)

## Possible Extensions (great for making the project stand out further)
- Build a simple web frontend (HTML/React) that calls this logic via a Flask/Node API
- Add a bigger common-password wordlist (e.g., the `rockyou.txt` top 10k)
- Add password generation suggestions based on the feedback
- Log check history locally (never log actual passwords — only ratings/timestamps)


