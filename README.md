

**Ultra Secure Unique Password Generator Pro** 
is a PyQt5 desktop app for generating cryptographically secure passwords with global uniqueness enforcement, live entropy/strength analysis, batch generation, and optional clipboard auto-clear.

---


# Ultra Secure Unique Password Generator Pro (PyQt5)

A professional desktop password generator built with **PyQt5**, focused on **security, usability, and reliability**.

This application generates **cryptographically secure passwords** using Python’s `secrets` / `SystemRandom`, while also enforcing **global uniqueness** through a **SHA-256 hash history** stored locally on the user’s machine. It includes a modern GUI, live entropy and strength feedback, brute-force time estimation, batch generation, session history, persistent settings, and an optional clipboard auto-clear feature for better operational security.

Whether you need strong passwords for personal use, testing, or secure workflows, this tool is designed to provide a practical and security-aware experience.

---

## Key Features

* **Cryptographically Secure Password Generation**

  * Uses `secrets.SystemRandom()` for strong randomness.
  * Avoids predictable or weak random generation methods.

* **Global Uniqueness Enforcement**

  * Prevents generating the same password twice (across sessions).
  * Stores only **SHA-256 hashes** in a local history file (not plaintext passwords).

* **Best-Effort Cross-Process Locking**

  * Reduces duplicate risk when multiple app instances run at the same time.
  * Supports Unix-like systems (`fcntl`) and Windows (`msvcrt`) where available.

* **Live Security Metrics**

  * Entropy estimation (bits)
  * Strength classification (Very weak → Very strong)
  * Brute-force time estimate (based on configurable guess rate assumptions)

* **Flexible Password Policy Controls**

  * Adjustable length and batch size
  * Lowercase / Uppercase / Digits / Symbols
  * Optional custom characters
  * Exclude similar-looking characters (e.g., `0/O`, `1/l/I`)
  * Avoid repeated characters option

* **Batch Generation + Session History**

  * Generate multiple unique passwords at once
  * Review generated passwords in a session history panel

* **Settings Persistence**

  * Saves preferences using `QSettings` (length, selected groups, options, UI state)

* **Clipboard Security Option**

  * Optional automatic clipboard clearing after a delay

---

## Security Notes

* Passwords are generated using **cryptographically secure randomness**.
* The app stores only **SHA-256 hashes** for uniqueness tracking, not the plaintext passwords.
* Entropy estimates are useful approximations and assume near-uniform selection from the active alphabet.
* For best security practice, store generated passwords in a **reputable password manager**.

---

## Tech Stack

* **Python 3**
* **PyQt5**
* Standard library security modules:

  * `secrets`
  * `hashlib`
  * `math`
  * `pathlib`
  * `QSettings` (via PyQt5)

---

## Ideal Use Cases

* Generating strong passwords for personal accounts
* Security-conscious local password generation workflows
* Desktop utility projects / PyQt5 portfolio showcase
* Learning example for:

  * secure randomness
  * GUI app architecture
  * local persistence
  * file locking (cross-platform best effort)

---

