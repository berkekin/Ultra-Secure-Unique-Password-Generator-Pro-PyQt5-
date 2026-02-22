# -*- coding: utf-8 -*-
"""
Ultra Secure Unique Password Generator Pro (PyQt5)

Key features
- Cryptographically secure password generation (secrets/SystemRandom).
- Global uniqueness enforcement via SHA-256 hash history file (stored in user's home directory).
- Best-effort cross-process locking to avoid duplicates when multiple instances run concurrently.
- Live entropy preview, strength indicator, brute-force time estimate.
- Batch generation + session history.
- Settings persistence via QSettings.
- Optional clipboard auto-clear for better operational security.

Notes on security
- Entropy estimates assume uniform selection from the effective alphabet. Enforcing “at least one
  from each selected group” slightly constrains the space; the estimate remains a useful approximation.
- Hash history stores only SHA-256 hashes (not plaintext passwords). Treat the history file as sensitive
  metadata and keep local machine access protected.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import secrets
import string
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Set, Tuple

from PyQt5 import QtCore, QtGui, QtWidgets

# -------------------------
# Application Constants
# -------------------------

APP_ORG = "UltraSecureTools"
APP_NAME = "PasswordGeneratorPro"
APP_TITLE = "Ultra Secure Unique Password Generator Pro"

DEFAULT_LENGTH = 16
MIN_LENGTH = 6
MAX_LENGTH = 128

DEFAULT_BATCH = 1
MIN_BATCH = 1
MAX_BATCH = 100

# Default attacker budget for estimate (commonly used illustrative order of magnitude).
DEFAULT_GUESSES_PER_SECOND = 1e10

# Common “ambiguous/similar-looking” characters, for human usability.
SIMILAR_CHARS = set("0Ool1I5S2Z6G8B")

# Printable symbols set (excluding whitespace).
DEFAULT_SYMBOLS = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""

# Clipboard auto-clear (optional)
DEFAULT_CLIPBOARD_CLEAR_ENABLED = False
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30


# -------------------------
# Logging (quiet by default)
# -------------------------

logger = logging.getLogger(__name__)


# -------------------------
# Cross-platform file locking (best effort)
# -------------------------

try:
    import fcntl  # type: ignore
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore

try:
    import msvcrt  # type: ignore
except Exception:  # pragma: no cover
    msvcrt = None  # type: ignore


class _FileLock:
    """
    Best-effort exclusive lock for a file object.

    - On Unix-like systems: uses fcntl.flock.
    - On Windows: uses msvcrt.locking on a small region.

    If locking isn't available or fails, we continue without locking (best-effort).
    """

    def __init__(self, file_obj) -> None:
        self._file = file_obj

    def __enter__(self):
        try:
            if fcntl is not None:
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
            elif msvcrt is not None:
                # Lock 1 byte at the start of file.
                self._file.seek(0)
                msvcrt.locking(self._file.fileno(), msvcrt.LK_LOCK, 1)
        except Exception:
            # Best effort: continue without lock
            logger.debug("File locking unavailable/failed; continuing unlocked.", exc_info=True)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if fcntl is not None:
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:
                self._file.seek(0)
                msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            logger.debug("File unlock unavailable/failed; continuing.", exc_info=True)


# =========================
#   CORE PASSWORD ENGINE
# =========================

class PasswordGeneratorCore:
    """
    Cryptographically secure password generator with global uniqueness enforcement.

    Uniqueness mechanism
    - Uses SHA-256(password) stored line-by-line in a history file.
    - On generation, a candidate password is accepted only if its hash is not present.
    - Uses best-effort file locking to reduce the chance of cross-process duplicates.

    Design goals
    - Clear correctness constraints (length, alphabet, group guarantees).
    - Strong randomness and no accidental bias.
    - Defensive I/O handling (generation continues even if history file can't be used).
    """

    def __init__(self, history_path: Optional[Path] = None) -> None:
        if history_path is None:
            history_path = Path.home() / ".unique_password_hashes.txt"

        self.history_path: Path = history_path
        self._rng = secrets.SystemRandom()
        self._used_hashes: Set[str] = set()

        self._ensure_history_file_secure()
        self._load_history_best_effort()

    # ---------- FILE / HISTORY ----------

    def _ensure_history_file_secure(self) -> None:
        """
        Create the history file if it doesn't exist.

        On POSIX platforms we try to create it with 0o600 permissions.
        If creation fails or platform doesn't support it, we fall back silently.
        """
        try:
            if self.history_path.exists():
                return

            # Create file with restricted permissions if possible.
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            mode = 0o600
            fd = os.open(str(self.history_path), flags, mode)
            os.close(fd)
        except FileExistsError:
            return
        except Exception:
            # Not fatal; uniqueness within current session still works.
            logger.debug("Could not securely create history file.", exc_info=True)

    def _load_history_best_effort(self) -> None:
        """Load hashes from disk into memory (best-effort)."""
        if not self.history_path.exists():
            return

        try:
            with self.history_path.open("r", encoding="utf-8") as f:
                for line in f:
                    h = line.strip()
                    if h:
                        self._used_hashes.add(h)
        except Exception:
            logger.debug("Failed to load history file; proceeding without cross-session history.", exc_info=True)

    @staticmethod
    def _hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _record_hash_if_new(self, pwd_hash: str) -> bool:
        """
        Atomically (best-effort) record a hash if it is not already present.

        Returns:
            True if recorded (new hash),
            False if already present (duplicate).
        """
        # Fast-path: if already in memory, it's definitely not new.
        if pwd_hash in self._used_hashes:
            return False

        # If we cannot use disk, uniqueness is in-memory only.
        try:
            # a+ allows read + append; we lock during check+append.
            with self.history_path.open("a+", encoding="utf-8") as f, _FileLock(f):
                # Reconcile with disk under lock (handles concurrent writers).
                f.seek(0)
                for line in f:
                    h = line.strip()
                    if h:
                        self._used_hashes.add(h)

                if pwd_hash in self._used_hashes:
                    return False

                # Append at end
                f.seek(0, os.SEEK_END)
                f.write(pwd_hash + "\n")
                f.flush()

                self._used_hashes.add(pwd_hash)
                return True
        except Exception:
            # Disk failed: fall back to in-memory uniqueness.
            logger.debug("History file write failed; enforcing uniqueness in-memory only.", exc_info=True)
            self._used_hashes.add(pwd_hash)
            return True

    # ---------- ENTROPY / SECURITY ESTIMATES ----------

    @staticmethod
    def estimate_entropy_bits(length: int, alphabet_size: int) -> float:
        """Return Shannon entropy (bits) for a uniformly random password from an alphabet."""
        if length <= 0 or alphabet_size <= 1:
            return 0.0
        return float(length) * math.log2(float(alphabet_size))

    @staticmethod
    def classify_strength(entropy_bits: float) -> str:
        """Human-friendly strength label from entropy estimate."""
        if entropy_bits < 40:
            return "Very weak"
        if entropy_bits < 60:
            return "Weak"
        if entropy_bits < 80:
            return "Reasonable"
        if entropy_bits < 100:
            return "Strong"
        return "Very strong"

    @staticmethod
    def format_bruteforce_time(entropy_bits: float, guesses_per_second: float = DEFAULT_GUESSES_PER_SECOND) -> str:
        """
        Rough brute-force time estimate based on entropy (log-space to avoid overflow).
        Expected time ~ 2^(H-1) / guesses_per_second
        """
        if entropy_bits <= 0:
            return f"< 1 second at {guesses_per_second:.0e} guesses/second."

        gps = max(float(guesses_per_second), 1.0)
        log2_time_seconds = entropy_bits - math.log2(2.0 * gps)

        if log2_time_seconds < 0:
            return f"< 1 second at {gps:.0e} guesses/second."

        log10_time_seconds = log2_time_seconds * math.log10(2.0)

        seconds_per_day = 60.0 * 60.0 * 24.0
        seconds_per_year = seconds_per_day * 365.25

        log10_years = log10_time_seconds - math.log10(seconds_per_year)

        if log10_years < -2:
            # under ~0.01 years: show days
            log10_days = log10_time_seconds - math.log10(seconds_per_day)
            approx_days = 10.0 ** log10_days
            return f"≈ {approx_days:.1f} days at {gps:.0e} guesses/second."

        if log10_years < 2:
            approx_years = 10.0 ** log10_years
            return f"≈ {approx_years:.2f} years at {gps:.0e} guesses/second."

        return f"≈ 10^{log10_years:.1f} years at {gps:.0e} guesses/second."

    # ---------- GENERATION ----------

    def _generate_single(
        self,
        length: int,
        group_char_sets: Sequence[str],
        full_alphabet: str,
        avoid_repeats: bool,
    ) -> str:
        """
        Generate a single password (does NOT enforce global uniqueness).
        Guarantees at least one character from each selected group.

        Raises:
            ValueError for invalid constraints.
        """
        if length <= 0:
            raise ValueError("Password length must be positive.")
        if not full_alphabet:
            raise ValueError("Alphabet is empty; no characters to choose from.")
        if len(group_char_sets) > length:
            raise ValueError(
                "Password length is too small to include at least one character "
                "from each selected group."
            )

        # Make a stable set of unique characters for no-repeat mode.
        full_unique_sorted = "".join(sorted(set(full_alphabet)))

        if avoid_repeats and length > len(full_unique_sorted):
            raise ValueError(
                "Password length exceeds the number of distinct characters available "
                "while avoiding repetitions."
            )

        chars: List[str] = []

        if avoid_repeats:
            used: Set[str] = set()

            # Pick one unique char from each group, if possible.
            for group in group_char_sets:
                group_unique = set(group)
                candidates = list(group_unique - used)
                if not candidates:
                    raise ValueError(
                        "Cannot satisfy both 'avoid repeats' and 'at least one from each group' "
                        "because the selected groups overlap too much (or a group is too small)."
                    )
                c = self._rng.choice(candidates)
                chars.append(c)
                used.add(c)

            remaining = length - len(chars)

            # Fill remaining from characters not already used.
            available = [c for c in full_unique_sorted if c not in used]
            for _ in range(remaining):
                idx = self._rng.randrange(len(available))
                c = available.pop(idx)
                chars.append(c)

        else:
            # Group guarantees (duplicates allowed)
            for group in group_char_sets:
                if group:
                    chars.append(self._rng.choice(group))

            remaining = length - len(chars)
            for _ in range(remaining):
                chars.append(self._rng.choice(full_alphabet))

        # Shuffle for uniform placement of “guarantee” chars.
        self._rng.shuffle(chars)
        return "".join(chars)

    def generate_unique_password(
        self,
        length: int,
        group_char_sets: Sequence[str],
        full_alphabet: str,
        avoid_repeats: bool,
        max_attempts: int = 100_000,
    ) -> str:
        """
        Generate a password that has never been produced before by this application,
        based on SHA-256 hash history.

        Raises:
            ValueError for invalid constraints.
            RuntimeError if the space is exhausted (or max_attempts hit).
        """
        last_error: Optional[Exception] = None

        for _ in range(max_attempts):
            try:
                pwd = self._generate_single(length, group_char_sets, full_alphabet, avoid_repeats)
            except Exception as e:
                last_error = e
                break

            h = self._hash_password(pwd)
            if self._record_hash_if_new(h):
                return pwd

        if last_error is not None:
            raise last_error

        raise RuntimeError(
            "Unable to generate a new unique password after many attempts. "
            "The search space might be exhausted for the chosen settings."
        )


# =========================
#   UI HELPERS / MODELS
# =========================

@dataclass(frozen=True)
class PolicySnapshot:
    length: int
    batch: int
    groups: List[str]
    alphabet: str
    avoid_repeats: bool


@dataclass(frozen=True)
class MetricsSnapshot:
    alphabet_size: int
    entropy_bits: float
    strength: str
    brute_force_time: str


# =========================
#        MAIN WINDOW
# =========================

class MainWindow(QtWidgets.QMainWindow):
    """
    Professional GUI for the password generator.

    - Configuration panel (policy)
    - Output panel (password + metrics)
    - Session history
    - Settings persistence (QSettings)
    """

    def __init__(self) -> None:
        super().__init__()

        self.core = PasswordGeneratorCore()
        self.settings = QtCore.QSettings(APP_ORG, APP_NAME)

        self.setWindowTitle(APP_TITLE)
        self.setMinimumSize(900, 550)

        self._clipboard_clear_timer: Optional[QtCore.QTimer] = None
        self._last_copied_value: str = ""

        self._apply_global_styles()
        self._build_ui()
        self._load_settings()
        self.update_live_preview()

    # ---------- UI CONSTRUCTION ----------

    def _build_ui(self) -> None:
        central = QtWidgets.QWidget(self)
        self.setCentralWidget(central)

        self._main_layout = QtWidgets.QVBoxLayout(central)

        self._build_toolbar()
        self._build_menu_bar()

        # Top area: configuration + output
        top_layout = QtWidgets.QHBoxLayout()
        self._main_layout.addLayout(top_layout, stretch=3)

        self._config_group = self._build_config_panel()
        top_layout.addWidget(self._config_group, stretch=2)

        self._output_group = self._build_output_panel()
        top_layout.addWidget(self._output_group, stretch=3)

        # Bottom: session history
        self.history_group = self._build_history_panel()
        self._main_layout.addWidget(self.history_group, stretch=2)

        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready.")

    def _build_config_panel(self) -> QtWidgets.QGroupBox:
        group = QtWidgets.QGroupBox("Password Policy")
        layout = QtWidgets.QVBoxLayout(group)

        # Length row
        length_row = QtWidgets.QHBoxLayout()
        length_label = QtWidgets.QLabel("Length:")
        self.length_spin = QtWidgets.QSpinBox()
        self.length_spin.setRange(MIN_LENGTH, MAX_LENGTH)
        self.length_spin.setValue(DEFAULT_LENGTH)

        self.length_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.length_slider.setRange(MIN_LENGTH, MAX_LENGTH)
        self.length_slider.setValue(DEFAULT_LENGTH)

        # sync
        self.length_spin.valueChanged.connect(self.length_slider.setValue)
        self.length_slider.valueChanged.connect(self.length_spin.setValue)

        length_row.addWidget(length_label)
        length_row.addWidget(self.length_spin)
        length_row.addWidget(self.length_slider)
        layout.addLayout(length_row)

        # Batch row
        batch_row = QtWidgets.QHBoxLayout()
        batch_label = QtWidgets.QLabel("Generate batch:")
        self.batch_spin = QtWidgets.QSpinBox()
        self.batch_spin.setRange(MIN_BATCH, MAX_BATCH)
        self.batch_spin.setValue(DEFAULT_BATCH)
        batch_row.addWidget(batch_label)
        batch_row.addWidget(self.batch_spin)
        layout.addLayout(batch_row)

        # Character sets
        self.lower_cb = QtWidgets.QCheckBox("Lowercase (a–z)")
        self.upper_cb = QtWidgets.QCheckBox("Uppercase (A–Z)")
        self.digits_cb = QtWidgets.QCheckBox("Digits (0–9)")
        self.symbols_cb = QtWidgets.QCheckBox("Symbols (!@#$...)")

        self.lower_cb.setChecked(True)
        self.upper_cb.setChecked(True)
        self.digits_cb.setChecked(True)
        self.symbols_cb.setChecked(True)

        layout.addWidget(self.lower_cb)
        layout.addWidget(self.upper_cb)
        layout.addWidget(self.digits_cb)
        layout.addWidget(self.symbols_cb)

        # Options
        self.exclude_similar_cb = QtWidgets.QCheckBox(
            "Exclude similar characters (0/O, 1/l/I, 5/S, 2/Z, 6/G, 8/B)"
        )
        self.no_repeat_cb = QtWidgets.QCheckBox("Avoid repeated characters in a password")
        layout.addWidget(self.exclude_similar_cb)
        layout.addWidget(self.no_repeat_cb)

        # Custom characters
        custom_form = QtWidgets.QFormLayout()
        self.custom_chars_edit = QtWidgets.QLineEdit()
        self.custom_chars_edit.setPlaceholderText("Optional: extra characters to include (e.g. _-#@)")
        custom_form.addRow("Custom chars:", self.custom_chars_edit)
        layout.addLayout(custom_form)

        # Live preview label
        self.live_entropy_label = QtWidgets.QLabel("Live entropy preview will update as you change settings.")
        self.live_entropy_label.setWordWrap(True)
        layout.addWidget(self.live_entropy_label)

        layout.addStretch(1)

        # Live preview signals
        self.length_spin.valueChanged.connect(self.update_live_preview)
        self.batch_spin.valueChanged.connect(self.update_live_preview)

        for cb in (self.lower_cb, self.upper_cb, self.digits_cb, self.symbols_cb, self.exclude_similar_cb, self.no_repeat_cb):
            cb.stateChanged.connect(self.update_live_preview)

        self.custom_chars_edit.textChanged.connect(self.update_live_preview)

        return group

    def _build_output_panel(self) -> QtWidgets.QGroupBox:
        group = QtWidgets.QGroupBox("Output & Security Metrics")
        layout = QtWidgets.QVBoxLayout(group)

        mono_font = QtGui.QFont("Consolas")
        mono_font.setStyleHint(QtGui.QFont.TypeWriter)

        # Password output
        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setReadOnly(True)
        self.password_edit.setFont(mono_font)
        self.password_edit.setPlaceholderText("Click “Generate” to create a unique password.")
        layout.addWidget(self.password_edit)

        # Buttons
        btn_row = QtWidgets.QHBoxLayout()
        self.generate_btn = QtWidgets.QPushButton("Generate")
        self.copy_btn = QtWidgets.QPushButton("Copy")
        self.clear_btn = QtWidgets.QPushButton("Clear")

        btn_row.addWidget(self.generate_btn)
        btn_row.addWidget(self.copy_btn)
        btn_row.addWidget(self.clear_btn)
        layout.addLayout(btn_row)

        # Strength
        strength_row = QtWidgets.QHBoxLayout()
        self.strength_bar = QtWidgets.QProgressBar()
        self.strength_bar.setRange(0, MAX_LENGTH)  # Visualization cap; we color-code via stylesheet.
        self.strength_bar.setFormat("Strength")
        self.strength_bar.setTextVisible(True)

        self.strength_label = QtWidgets.QLabel("Strength: N/A")

        strength_row.addWidget(self.strength_bar, stretch=3)
        strength_row.addWidget(self.strength_label, stretch=2)
        layout.addLayout(strength_row)

        # Metrics label
        self.metrics_label = QtWidgets.QLabel("Detailed metrics will appear here after generation.")
        self.metrics_label.setWordWrap(True)
        layout.addWidget(self.metrics_label)

        # Clipboard safety option
        self.clipboard_clear_cb = QtWidgets.QCheckBox(
            f"Auto-clear clipboard after {DEFAULT_CLIPBOARD_CLEAR_SECONDS} seconds (recommended on shared machines)"
        )
        self.clipboard_clear_cb.setChecked(DEFAULT_CLIPBOARD_CLEAR_ENABLED)
        layout.addWidget(self.clipboard_clear_cb)

        # Connections
        self.generate_btn.clicked.connect(self.on_generate_clicked)
        self.copy_btn.clicked.connect(self.on_copy_clicked)
        self.clear_btn.clicked.connect(self.on_clear_clicked)

        return group

    def _build_history_panel(self) -> QtWidgets.QGroupBox:
        group = QtWidgets.QGroupBox("Session History")
        layout = QtWidgets.QVBoxLayout(group)

        mono_font = QtGui.QFont("Consolas")
        mono_font.setStyleHint(QtGui.QFont.TypeWriter)

        self.history_edit = QtWidgets.QPlainTextEdit()
        self.history_edit.setReadOnly(True)
        self.history_edit.setFont(mono_font)
        self.history_edit.setPlaceholderText(
            "Each generated password (for this session) will appear here.\n"
            "Uniqueness is enforced globally using a hash history stored in your home directory."
        )
        layout.addWidget(self.history_edit)

        # Clear history button
        clear_history_row = QtWidgets.QHBoxLayout()
        clear_history_row.addStretch(1)
        self.clear_history_btn = QtWidgets.QPushButton("Clear History")
        clear_history_row.addWidget(self.clear_history_btn)
        layout.addLayout(clear_history_row)

        self.clear_history_btn.clicked.connect(self.on_clear_history_clicked)

        return group

    def _build_toolbar(self) -> None:
        toolbar = QtWidgets.QToolBar("Main Toolbar")
        toolbar.setIconSize(QtCore.QSize(20, 20))
        self.addToolBar(toolbar)

        style = self.style()

        def add_action(text: str, icon, shortcut: str, handler, status_tip: str) -> QtWidgets.QAction:
            action = QtWidgets.QAction(icon, text, self)
            action.setShortcut(shortcut)
            action.setStatusTip(status_tip)
            action.triggered.connect(handler)
            toolbar.addAction(action)
            return action

        add_action(
            "Generate password",
            style.standardIcon(QtWidgets.QStyle.SP_MediaPlay),
            "Ctrl+G",
            self.on_generate_clicked,
            "Generate a new unique password",
        )
        add_action(
            "Copy to clipboard",
            style.standardIcon(QtWidgets.QStyle.SP_DialogSaveButton),
            "Ctrl+C",
            self.on_copy_clicked,
            "Copy the current password to clipboard",
        )
        add_action(
            "Clear output",
            style.standardIcon(QtWidgets.QStyle.SP_DialogResetButton),
            "Ctrl+L",
            self.on_clear_clicked,
            "Clear the current password output",
        )

        toolbar.addSeparator()

        add_action(
            "About",
            style.standardIcon(QtWidgets.QStyle.SP_MessageBoxInformation),
            "F1",
            self.show_about_dialog,
            "About this application",
        )

    def _build_menu_bar(self) -> None:
        menubar = self.menuBar()

        # File
        file_menu = menubar.addMenu("&File")
        exit_action = QtWidgets.QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View
        view_menu = menubar.addMenu("&View")
        self.toggle_history_action = QtWidgets.QAction("Show session &history", self, checkable=True)
        self.toggle_history_action.setChecked(True)
        self.toggle_history_action.triggered.connect(self.toggle_history_visibility)
        view_menu.addAction(self.toggle_history_action)

        # Help
        help_menu = menubar.addMenu("&Help")
        about_action = QtWidgets.QAction("&About", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

    # ---------- STYLES ----------

    def _apply_global_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background-color: #202124; }

            QGroupBox {
                color: #ffffff;
                font-weight: 600;
                border: 1px solid #444;
                border-radius: 8px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 4px;
            }

            QLabel { color: #e8eaed; }

            QLineEdit, QPlainTextEdit {
                background-color: #303134;
                color: #e8eaed;
                border-radius: 4px;
                padding: 4px;
                border: 1px solid #555;
            }

            QSpinBox, QSlider, QCheckBox, QMenuBar, QMenu, QStatusBar {
                color: #e8eaed;
                background-color: #202124;
            }

            QPushButton {
                background-color: #1a73e8;
                color: #ffffff;
                border-radius: 4px;
                padding: 6px 12px;
                border: 1px solid #1a73e8;
            }
            QPushButton:hover { background-color: #4285f4; }
            QPushButton:pressed { background-color: #3367d6; }

            QProgressBar {
                border: 1px solid #555;
                border-radius: 4px;
                text-align: center;
                background-color: #303134;
                color: #e8eaed;
            }
            QProgressBar::chunk {
                border-radius: 4px;
                margin: 0px;
            }
            """
        )

    def _set_strength_bar_style(self, strength: str) -> None:
        # Color-coded chunk for quick visual feedback.
        color = "#d32f2f"  # red
        if strength == "Weak":
            color = "#f57c00"  # orange
        elif strength == "Reasonable":
            color = "#fbc02d"  # yellow
        elif strength == "Strong":
            color = "#388e3c"  # green
        elif strength == "Very strong":
            color = "#2e7d32"  # darker green

        self.strength_bar.setStyleSheet(
            f"""
            QProgressBar {{
                border: 1px solid #555;
                border-radius: 4px;
                text-align: center;
                background-color: #303134;
                color: #e8eaed;
            }}
            QProgressBar::chunk {{
                border-radius: 4px;
                margin: 0px;
                background-color: {color};
            }}
            """
        )

    # ---------- SETTINGS ----------

    def _load_settings(self) -> None:
        self.restoreGeometry(self.settings.value("geometry", b""))

        self.length_spin.setValue(self.settings.value("length", DEFAULT_LENGTH, type=int))
        self.batch_spin.setValue(self.settings.value("batch", DEFAULT_BATCH, type=int))

        self.lower_cb.setChecked(self.settings.value("lower", True, type=bool))
        self.upper_cb.setChecked(self.settings.value("upper", True, type=bool))
        self.digits_cb.setChecked(self.settings.value("digits", True, type=bool))
        self.symbols_cb.setChecked(self.settings.value("symbols", True, type=bool))

        self.exclude_similar_cb.setChecked(self.settings.value("exclude_similar", False, type=bool))
        self.no_repeat_cb.setChecked(self.settings.value("no_repeat", False, type=bool))
        self.custom_chars_edit.setText(self.settings.value("custom_chars", "", type=str))

        self.clipboard_clear_cb.setChecked(
            self.settings.value("clipboard_clear", DEFAULT_CLIPBOARD_CLEAR_ENABLED, type=bool)
        )

        history_visible = self.settings.value("history_visible", True, type=bool)
        self.toggle_history_action.setChecked(history_visible)
        self.history_group.setVisible(history_visible)

    def _save_settings(self) -> None:
        self.settings.setValue("geometry", self.saveGeometry())

        self.settings.setValue("length", self.length_spin.value())
        self.settings.setValue("batch", self.batch_spin.value())

        self.settings.setValue("lower", self.lower_cb.isChecked())
        self.settings.setValue("upper", self.upper_cb.isChecked())
        self.settings.setValue("digits", self.digits_cb.isChecked())
        self.settings.setValue("symbols", self.symbols_cb.isChecked())

        self.settings.setValue("exclude_similar", self.exclude_similar_cb.isChecked())
        self.settings.setValue("no_repeat", self.no_repeat_cb.isChecked())
        self.settings.setValue("custom_chars", self.custom_chars_edit.text())

        self.settings.setValue("clipboard_clear", self.clipboard_clear_cb.isChecked())
        self.settings.setValue("history_visible", self.history_group.isVisible())

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self._save_settings()
        super().closeEvent(event)

    # ---------- CHARACTER SET BUILDING ----------

    @staticmethod
    def _unique_sorted(chars: str) -> str:
        return "".join(sorted(set(chars)))

    def _filter_chars(self, chars: str, exclude_similar: bool) -> str:
        if not exclude_similar:
            return self._unique_sorted(chars)
        return "".join(sorted({c for c in chars if c not in SIMILAR_CHARS}))

    def _build_char_sets(self) -> Tuple[List[str], str]:
        exclude_similar = self.exclude_similar_cb.isChecked()
        groups: List[str] = []

        if self.lower_cb.isChecked():
            g = self._filter_chars(string.ascii_lowercase, exclude_similar)
            if g:
                groups.append(g)
        if self.upper_cb.isChecked():
            g = self._filter_chars(string.ascii_uppercase, exclude_similar)
            if g:
                groups.append(g)
        if self.digits_cb.isChecked():
            g = self._filter_chars(string.digits, exclude_similar)
            if g:
                groups.append(g)
        if self.symbols_cb.isChecked():
            g = self._filter_chars(DEFAULT_SYMBOLS, exclude_similar)
            if g:
                groups.append(g)

        # Custom characters are treated as explicit user intent; we keep them as-is (deduped),
        # even if "exclude similar" is checked.
        custom = self.custom_chars_edit.text()
        if custom:
            g = self._unique_sorted(custom)
            if g:
                groups.append(g)

        alphabet = self._unique_sorted("".join(groups))
        return groups, alphabet

    def _read_policy(self) -> PolicySnapshot:
        groups, alphabet = self._build_char_sets()
        return PolicySnapshot(
            length=self.length_spin.value(),
            batch=self.batch_spin.value(),
            groups=groups,
            alphabet=alphabet,
            avoid_repeats=self.no_repeat_cb.isChecked(),
        )

    def _compute_metrics(self, length: int, alphabet: str) -> MetricsSnapshot:
        alphabet_size = len(set(alphabet))
        entropy_bits = self.core.estimate_entropy_bits(length, alphabet_size)
        strength = self.core.classify_strength(entropy_bits)
        brute = self.core.format_bruteforce_time(entropy_bits, DEFAULT_GUESSES_PER_SECOND)
        return MetricsSnapshot(
            alphabet_size=alphabet_size,
            entropy_bits=entropy_bits,
            strength=strength,
            brute_force_time=brute,
        )

    # ---------- LIVE PREVIEW ----------

    def update_live_preview(self) -> None:
        policy = self._read_policy()

        if not policy.alphabet:
            self.live_entropy_label.setText("Live entropy preview: no characters selected.")
            self.strength_bar.setValue(0)
            self.strength_label.setText("Strength: N/A")
            self.metrics_label.setText("Preview unavailable: select at least one character group.")
            return

        metrics = self._compute_metrics(policy.length, policy.alphabet)

        self.live_entropy_label.setText(
            f"Alphabet size: {metrics.alphabet_size} | "
            f"Estimated entropy: {metrics.entropy_bits:.2f} bits ({metrics.strength})"
        )

        # Visualization: map entropy onto the progress bar range (0..MAX_LENGTH).
        value = int(min(max(metrics.entropy_bits, 0.0), float(MAX_LENGTH)))
        self.strength_bar.setValue(value)
        self.strength_label.setText(f"Strength: {metrics.strength}")
        self._set_strength_bar_style(metrics.strength)

        self.metrics_label.setText(
            "Preview:\n"
            f" - Length: {policy.length}\n"
            f" - Alphabet size: {metrics.alphabet_size}\n"
            f" - Entropy (estimated): {metrics.entropy_bits:.2f} bits ({metrics.strength})\n"
            f" - Estimated brute-force time: {metrics.brute_force_time}"
        )

    # ---------- ACTIONS ----------

    def on_generate_clicked(self) -> None:
        policy = self._read_policy()

        if not policy.alphabet:
            QtWidgets.QMessageBox.warning(
                self,
                "No characters selected",
                "Please select at least one character group or provide custom characters.",
            )
            return

        if len(policy.groups) > policy.length:
            QtWidgets.QMessageBox.warning(
                self,
                "Length too short",
                "Password length is too short to guarantee at least one character\n"
                "from each selected group. Increase length or deselect groups.",
            )
            return

        generated: List[str] = []
        try:
            for _ in range(policy.batch):
                pwd = self.core.generate_unique_password(
                    length=policy.length,
                    group_char_sets=policy.groups,
                    full_alphabet=policy.alphabet,
                    avoid_repeats=policy.avoid_repeats,
                )
                generated.append(pwd)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Generation error", f"Password generation failed:\n{e}")
            return

        # Output
        last_password = generated[-1]
        self.password_edit.setText(last_password)

        # Session history (append block)
        existing = self.history_edit.toPlainText().rstrip()
        block = "\n".join(generated)
        self.history_edit.setPlainText((existing + "\n" + block).strip() if existing else block)

        # Metrics (same policy for batch)
        metrics = self._compute_metrics(policy.length, policy.alphabet)
        self.metrics_label.setText(
            f"Generated {policy.batch} unique password(s).\n"
            f"Length: {policy.length} characters\n"
            f"Alphabet size: {metrics.alphabet_size} unique characters\n"
            f"Estimated entropy: {metrics.entropy_bits:.2f} bits ({metrics.strength})\n"
            f"Approximate brute-force time: {metrics.brute_force_time}"
        )

        self.status_bar.showMessage(f"Generated {policy.batch} unique password(s).", 8000)

    def on_copy_clicked(self) -> None:
        pwd = self.password_edit.text()
        if not pwd:
            self.status_bar.showMessage("No password to copy.", 5000)
            return

        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(pwd)

        self._last_copied_value = pwd
        self.status_bar.showMessage("Password copied to clipboard.", 5000)

        if self.clipboard_clear_cb.isChecked():
            self._schedule_clipboard_clear(seconds=DEFAULT_CLIPBOARD_CLEAR_SECONDS)

    def _schedule_clipboard_clear(self, seconds: int) -> None:
        # Cancel previous timer if any
        if self._clipboard_clear_timer is not None:
            self._clipboard_clear_timer.stop()
            self._clipboard_clear_timer.deleteLater()
            self._clipboard_clear_timer = None

        timer = QtCore.QTimer(self)
        timer.setSingleShot(True)

        def clear_if_unchanged() -> None:
            clipboard = QtWidgets.QApplication.clipboard()
            if clipboard.text() == self._last_copied_value and self._last_copied_value:
                clipboard.clear()
                self.status_bar.showMessage("Clipboard cleared (auto-clear).", 5000)

        timer.timeout.connect(clear_if_unchanged)
        timer.start(max(1, seconds) * 1000)

        self._clipboard_clear_timer = timer

    def on_clear_clicked(self) -> None:
        self.password_edit.clear()
        # Keep history; reset preview/metrics display based on current settings
        self.update_live_preview()
        self.status_bar.showMessage("Output cleared.", 5000)

    def on_clear_history_clicked(self) -> None:
        self.history_edit.clear()
        self.status_bar.showMessage("Session history cleared.", 5000)

    def toggle_history_visibility(self, checked: bool) -> None:
        self.history_group.setVisible(bool(checked))

    def show_about_dialog(self) -> None:
        QtWidgets.QMessageBox.information(
            self,
            f"About {APP_TITLE}",
            (
                f"{APP_TITLE}\n\n"
                "• Cryptographically secure randomness (SystemRandom)\n"
                "• Global uniqueness via SHA-256 hash history stored in your home directory\n"
                "• Live entropy preview and brute-force time estimates\n"
                "• Batch generation + session history\n"
                "• Optional clipboard auto-clear\n\n"
                "Recommendation: store generated passwords in a reputable password manager.(This Program Created by Berk EKIN bekin@tu-sofia.bg)"
            ),
        )


# =========================
#          ENTRY
# =========================

def main() -> None:
    # High-DPI friendliness (must be set before app creation)
    try:
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)
    except Exception:
        pass

    # Optional: configure logging (keep quiet by default)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    app = QtWidgets.QApplication(sys.argv)
    app.setOrganizationName(APP_ORG)
    app.setApplicationName(APP_NAME)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()