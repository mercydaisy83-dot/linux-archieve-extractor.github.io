#!/usr/bin/env python3
"""
Archive Extractor v3.1 —  PySide6 application for Linux Mint Cinnamon.
Author: Nambafu Samuel Favor

Features: ZIP/TAR extraction in a background thread, path-traversal protection,
drag-and-drop, progress reporting, cancellation (including mid-file), conflict
skipping instead of silent overwrite, extracted-application detection, explicit
launching (binaries, scripts, and .desktop entries), .desktop menu shortcut
creation, desktop launchers, and folder opening.

"""
from __future__ import annotations

import os
import posixpath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import IO, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QListWidget,QListWidgetItem, QMainWindow, 
    QMessageBox,QProgressBar,QPushButton, QScrollArea, 
    QVBoxLayout, QWidget,
)
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication


APP_NAME = "Archive Extractor"
APP_VERSION = "3.1"

# ============================================================
# Design system (QSS)
# ============================================================

BG_MAIN, BG_CONTENT, BG_CARD, BG_SURFACE = "#07131F", "#0C1222", "#111D2D", "#162438"
BORDER, ACCENT, ACCENT_HOVER = "#1F2A38", "#06B6D4", "#22D3EE"
TEXT, TEXT_DIM = "#F1F5F9", "#94A3B8"
SUCCESS, WARNING, ERROR = "#34D399", "#FBBF24", "#F87171"

STYLESHEET = f"""
QWidget {{
    background: {BG_MAIN}; color: {TEXT};
    font-family: 'Ubuntu', 'Cantarell', 'Noto Sans', sans-serif; font-size: 13px;
}}
QMainWindow, QDialog {{ background: {BG_MAIN}; }}
#HeaderFrame {{ background: {BG_CONTENT}; border-bottom: 1px solid {BORDER}; }}
#AppTitle {{ font-size: 20px; font-weight: 700; color: {TEXT}; background: transparent; }}
#AppSubtitle {{ font-size: 12px; color: {TEXT_DIM}; background: transparent; }}
#VersionLabel {{
    color: {TEXT_DIM}; font-size: 11px; background: {BG_SURFACE};
    border: 1px solid {BORDER}; border-radius: 9px; padding: 2px 8px;
}}
#HeaderIcon {{ color: {ACCENT}; font-size: 26px; font-weight: 700; background: transparent; }}
#Card {{
    background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 10px;
}}
#CardTitle {{ font-size: 13px; font-weight: 600; color: {TEXT}; background: transparent; }}
#CardHint {{ font-size: 11px; color: {TEXT_DIM}; background: transparent; }}
QLineEdit {{
    background: {BG_SURFACE}; border: 1px solid {BORDER}; border-radius: 6px;
    padding: 7px 10px; color: {TEXT}; selection-background-color: {ACCENT};
}}
QLineEdit:focus {{ border: 1px solid {ACCENT}; }}
QPushButton {{
    background: {BG_SURFACE}; border: 1px solid {BORDER}; border-radius: 6px;
    padding: 8px 16px; color: {TEXT}; font-weight: 600;
}}
QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT_HOVER}; }}
QPushButton:pressed {{ background: {BG_CARD}; }}
QPushButton:disabled {{ color: {TEXT_DIM}; background: {BG_CARD}; border-color: {BORDER}; }}
#PrimaryButton {{
    background: {ACCENT}; border: 1px solid {ACCENT}; color: {BG_MAIN};
    font-weight: 700; padding: 10px 20px;
}}
#PrimaryButton:hover {{ background: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; color: {BG_MAIN}; }}
#PrimaryButton:disabled {{ background: {BG_SURFACE}; color: {TEXT_DIM}; border-color: {BORDER}; }}
#DangerButton {{ border-color: {ERROR}; color: {ERROR}; }}
#DangerButton:hover {{ background: {ERROR}; color: {BG_MAIN}; }}
#ProgressBar {{
    background: {BG_SURFACE}; border: 1px solid {BORDER}; border-radius: 6px;
    min-height: 12px; max-height: 12px; text-align: center; color: {TEXT}; font-size: 10px;
}}
#ProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}
QListWidget {{
    background: {BG_SURFACE}; border: 1px solid {BORDER}; border-radius: 6px; padding: 4px;
}}
QListWidget::item {{ padding: 6px 8px; border-radius: 4px; }}
QListWidget::item:selected {{ background: {ACCENT}; color: {BG_MAIN}; }}
QListWidget::item:hover:!selected {{ background: {BG_CARD}; }}
#StatusLabel {{ font-size: 12px; background: transparent; }}
#StatusLabel[state="ok"] {{ color: {SUCCESS}; }}
#StatusLabel[state="warn"] {{ color: {WARNING}; }}
#StatusLabel[state="error"] {{ color: {ERROR}; }}
#StatusLabel[state="idle"] {{ color: {TEXT_DIM}; }}
QCheckBox {{ background: transparent; color: {TEXT_DIM}; font-size: 12px; }}
QCheckBox::indicator {{
    width: 15px; height: 15px; border: 1px solid {BORDER}; border-radius: 3px;
    background: {BG_SURFACE};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: {BG_CONTENT}; width: 9px; border: none; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 4px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
#DropOverlay {{
    background: rgba(6, 182, 212, 0.08); border: 2px dashed {ACCENT};
    border-radius: 10px; color: {ACCENT_HOVER}; font-size: 15px; font-weight: 600;
}}
"""

# ============================================================
# Archive security
# ============================================================


def is_safe_member(name: str, dest_root: Path) -> bool:
    """True if *name* extracts safely under dest_root (no traversal/abs paths)."""
    if not name or "\x00" in name:
        return False
    p = PurePosixPath(name)
    if p.is_absolute() or name.startswith("\\") or (len(name) > 1 and name[1] == ":"):
        return False
    for part in p.parts:
        if part == "..":
            return False
    candidate = dest_root.joinpath(*(x for x in p.parts if x not in ("", ".")))
    root_real = os.path.realpath(dest_root)
    cand_real = os.path.realpath(candidate)
    return cand_real == root_real or cand_real.startswith(root_real + os.sep)


def safe_relative_path(name: str) -> str:
    """Normalized, traversal-free relative member name ('' if none)."""
    parts = [x for x in PurePosixPath(name).parts if x not in ("", ".", "..")]
    return posixpath.join(*parts) if parts else ""


# ============================================================
# Extraction engine
# ============================================================

ZIP_EXTS = (".zip",)
TAR_EXTS = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
SUPPORTED_EXTS = ZIP_EXTS + TAR_EXTS
UI_UPDATE_INTERVAL = 0.1   # seconds between progress signals
CHUNK_SIZE = 1024 * 256    # copy chunk size


def archive_kind(path: str) -> Optional[str]:
    lower = path.lower()
    if lower.endswith(ZIP_EXTS):
        return "zip"
    for ext in TAR_EXTS:
        if lower.endswith(ext):
            return "tar"
    return None


class ExtractCancelled(Exception):
    pass


class ExtractWorker(QThread):
    """Background extraction worker. Communicates only via signals."""

    progress = Signal(str, int, int, bool)   # current file, done, total, determinate
    finished_ok = Signal(str)                # dest path
    failed = Signal(str, str)                # friendly, technical
    rejected_entries = Signal(int)           # unsafe/unsupported entries skipped
    skipped_existing = Signal(int)           # existing files skipped (no overwrite)

    def __init__(self, archive_path: str, dest_path: str, parent=None) -> None:
        super().__init__(parent)
        self.archive_path = archive_path
        self.dest_path = dest_path
        self.recent_files: list[str] = []   # files extracted this run (for app detection)
        self._cancelled = False
        self._last_emit = 0.0

    def cancel(self) -> None:
        self._cancelled = True

    def _check_cancel(self) -> None:
        if self._cancelled:
            raise ExtractCancelled()

    def _emit(self, current: str, done: int, total: int, force: bool = False) -> None:
        now = time.monotonic()
        if force or (now - self._last_emit) >= UI_UPDATE_INTERVAL:
            self._last_emit = now
            self.progress.emit(current, done, total, total > 0)

    def _estimate_uncompressed(self) -> int:
        """Best-effort expanded size from archive metadata; 0 if unknown."""
        try:
            if archive_kind(self.archive_path) == "zip":
                with zipfile.ZipFile(self.archive_path) as zf:
                    return sum(i.file_size for i in zf.infolist())
            with tarfile.open(self.archive_path, "r:*") as tf:
                return sum(m.size for m in tf.getmembers() if m.isfile())
        except (OSError, zipfile.BadZipFile, tarfile.TarError, RuntimeError):
            return 0

    def _validate_free_space(self, needed_estimate: int = 0) -> None:
        # Prefer metadata-based estimate; fall back to archive-size × 2.
        needed = needed_estimate or os.path.getsize(self.archive_path) * 2
        needed = int(needed * 1.1) + 1  # 10% margin
        usage = shutil.disk_usage(self.dest_path)
        if needed > usage.free:
            raise OSError(
                f"Not enough free disk space (need roughly "
                f"{needed // (1024 * 1024)} MB, "
                f"available {usage.free // (1024 * 1024)} MB)."
            )

    def _copy_stream(self, src: IO[bytes], target: Path) -> None:
        """Chunked copy with mid-file cancellation. Removes partial output on cancel."""
        try:
            with src, open(target, "wb") as dst:
                while True:
                    self._check_cancel()
                    buf = src.read(CHUNK_SIZE)
                    if not buf:
                        return
                    dst.write(buf)
        except ExtractCancelled:
            try:
                target.unlink()
            except OSError:
                pass
            raise

    def _extract_zip(self) -> tuple[int, int, int]:
        with zipfile.ZipFile(self.archive_path) as zf:
            infos = zf.infolist()
            self._validate_free_space(sum(i.file_size for i in infos))
            unsafe = skipped = done = 0
            for info in infos:
                self._check_cancel()
                name = info.filename
                safe_rel = safe_relative_path(name)
                if not safe_rel:               # degenerate entry ('.', '/', '')
                    done += 1
                    continue
                if not is_safe_member(name, self.dest):
                    unsafe += 1
                    done += 1
                    continue
                target = self.dest / safe_rel
                if name.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    if os.path.lexists(target):   # never overwrite existing files
                        skipped += 1
                        done += 1
                        self._emit(name, done, len(infos))
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    self._copy_stream(zf.open(info), target)
                    mode = (info.external_attr >> 16) & 0o7777
                    if mode and stat.S_ISREG(info.external_attr >> 16):
                        os.chmod(target, mode)
                    self.recent_files.append(str(target))
                done += 1
                self._emit(name, done, len(infos))
            return unsafe, skipped, len(infos)

    
    def _extract_tar(self) -> tuple[int, int, int]:
        with tarfile.open(self.archive_path, "r:*") as tf:
            members = tf.getmembers()

            self._validate_free_space(
                sum(m.size for m in members if m.isfile())
            )

            root = self.dest.resolve()
            unsafe = skipped = done = 0
            pending_links = []

            def inside_destination(path: Path) -> bool:
                try:
                    resolved = path.resolve(strict=False)
                    return os.path.commonpath(
                    (str(root), str(resolved))
                    ) == str(root)
                except (OSError, ValueError, RuntimeError):
                    return False

            for member in members:
                self._check_cancel()

                safe_rel = safe_relative_path(member.name)

                if not safe_rel:
                    unsafe += 1
                    done += 1
                    continue

                if not is_safe_member(member.name, self.dest):
                    unsafe += 1
                    done += 1
                    continue

                target = self.dest / safe_rel

                if member.issym() or member.islnk():
                 # Defer links until ordinary files are extracted.
                    pending_links.append((member, safe_rel))
                    done += 1
                    self._emit(member.name, done, len(members))
                    continue

                if not member.isfile() and not member.isdir():
                    done += 1
                    self._emit(member.name, done, len(members))
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)

                # Do not write through a directory symlink outside
                # the extraction destination.
                if not inside_destination(target.parent):
                    unsafe += 1
                    done += 1
                    self._emit(member.name, done, len(members))
                    continue

                if member.isdir():
                    if os.path.lexists(target):
                        if not target.is_dir() or target.is_symlink():
                            skipped += 1
                    else:
                        target.mkdir(parents=True, exist_ok=True)

                else:
                    if os.path.lexists(target):
                        skipped += 1
                    else:
                        src = tf.extractfile(member)

                        if src is not None:
                            with src:
                                self._copy_stream(src, target)

                            os.chmod(target, member.mode & 0o777)
                            self.recent_files.append(str(target))

                done += 1
                self._emit(member.name, done, len(members))

            # Create links only after ordinary files have been extracted.
            # Retry links whose targets are other pending links.
            while pending_links:
                self._check_cancel()

                remaining = []
                created_this_pass = False

                for member, safe_rel in pending_links:
                    link_path = self.dest / safe_rel

                    if os.path.lexists(link_path):
                        skipped += 1
                        continue

                    try:
                        link_path.parent.mkdir(
                            parents=True, exist_ok=True
                        )

                        if not inside_destination(link_path.parent):
                            unsafe += 1
                            continue

                        if member.issym():
                            link_name = member.linkname

                            # Absolute symbolic-link targets are rejected.
                            if os.path.isabs(link_name):
                                unsafe += 1
                                continue

                            link_target = link_path.parent / link_name

                        else:
                            # TAR hard-link targets are archive-root-relative.
                            hard_rel = safe_relative_path(member.linkname)

                            if not hard_rel:
                                unsafe += 1
                                continue

                            link_target = self.dest / hard_rel

                        if not inside_destination(link_target):
                            unsafe += 1
                            continue

                        # Wait for targets that may themselves be pending links.
                        if not link_target.exists():
                            remaining.append((member, safe_rel))
                            continue

                        if member.islnk():
                            if not link_target.is_file():
                                unsafe += 1
                                continue

                            os.link(link_target, link_path)

                        else:
                            os.symlink(member.linkname, link_path)

                        created_this_pass = True

                    except (OSError, ValueError, RuntimeError):
                        unsafe += 1

                if not remaining:
                    break

                if not created_this_pass:
                    # Unresolved or broken links are rejected.
                    unsafe += len(remaining)
                    break

                pending_links = remaining

            return unsafe, skipped, len(members)

    def run(self) -> None:
        self.dest = Path(self.dest_path)
        try:
            self.dest.mkdir(parents=True, exist_ok=True)
            kind = archive_kind(self.archive_path)
            if kind == "zip":
                unsafe, skipped, total = self._extract_zip()
            elif kind == "tar":
                unsafe, skipped, total = self._extract_tar()
            else:
                raise ValueError("Unsupported archive format.")
            if total == 0:
                self.failed.emit("The archive is empty — nothing to extract.",
                                 "Archive contained zero members.")
                return
            if unsafe:
                self.rejected_entries.emit(unsafe)
            if skipped:
                self.skipped_existing.emit(skipped)
            self._emit("", total, total, force=True)
            if self._cancelled:
                self.failed.emit("Extraction was cancelled.", "Cancelled by user.")
                return
            self.finished_ok.emit(str(self.dest))
        except ExtractCancelled:
            self.failed.emit("Extraction was cancelled.", "Cancelled by user.")
        except (zipfile.BadZipFile, tarfile.TarError) as exc:
            self.failed.emit("The archive appears to be corrupted or is not a valid archive.",
                             f"{type(exc).__name__}: {exc}")
        except RuntimeError as exc:
            # zipfile raises RuntimeError for encrypted members.
            self.failed.emit("This archive may be password-protected or cannot be opened "
                             "in read mode.", f"RuntimeError: {exc}")
        except PermissionError as exc:
            self.failed.emit("Permission denied while extracting. Check destination permissions.",
                             f"{type(exc).__name__}: {exc}")
        except OSError as exc:
            if exc.errno == 28:
                self.failed.emit("Ran out of disk space while extracting.", f"OSError: {exc}")
            else:
                self.failed.emit("A filesystem error occurred during extraction.",
                                 f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # worker must never die silently
            self.failed.emit("An unexpected error occurred during extraction.",
                             f"{type(exc).__name__}: {exc}")


# ============================================================
# Application detection, launching, folder opening
# ============================================================


class AppCandidate:
    __slots__ = ("path", "name", "is_desktop_entry", "exec_argv", "workdir", "icon")

    def __init__(self, path: Path, name: str, is_desktop_entry: bool,
                 exec_argv: Optional[list[str]] = None,
                 workdir: Optional[str] = None, icon: str = "") -> None:
        self.path, self.name, self.is_desktop_entry = path, name, is_desktop_entry
        self.exec_argv, self.workdir, self.icon = exec_argv, workdir, icon


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _is_script(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(128).startswith(b"#!")
    except OSError:
        return False


def _parse_desktop_entry(path: Path) -> Optional[tuple[list[str], str, str]]:
    """Parse a .desktop entry: returns (exec_argv, workdir, icon) or None.

    Only the first [Desktop Entry] group is read; field codes (%f, %u, ...)
    are stripped since we cannot supply them.
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    in_main = False
    exec_line = workdir = icon = ""
    for line in lines:
        line = line.strip()
        if line.startswith("["):
            in_main = (line == "[Desktop Entry]")
            continue
        if not in_main or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key == "Exec":
            exec_line = value
        elif key == "Path":
            workdir = value
        elif key == "Icon":
            icon = value
    if not exec_line:
        return None
    # Resolve local icon paths relative to the .desktop file's directory.
    if icon and not icon.startswith("/"):
        local = path.parent / icon
        if local.is_file():
            icon = str(local)
    try:
        argv = shlex.split(exec_line, posix=True)
    except ValueError:
        return None
    # Strip field codes: a token that is exactly one % + a field-code letter.
    argv = [a for a in argv
            if not (len(a) == 2 and a.startswith("%") and a[1] in "fuFUdDinNvmk")]
    argv = [a for a in argv if a]
    if not argv:
        return None
    return argv, workdir, icon


def detect_applications(extracted_files: list[str]) -> list[AppCandidate]:
    """Inspect only files extracted this run. Never executes anything."""
    seen: set[Path] = set()
    candidates: list[AppCandidate] = []
    for raw in extracted_files:
        p = Path(raw)
        if p in seen or not p.is_file() or p.is_symlink():
            continue
        seen.add(p)
        if p.suffix == ".desktop":
            parsed = _parse_desktop_entry(p)
            if parsed:
                argv, workdir, icon = parsed
                candidates.append(AppCandidate(p, p.stem, True, argv, workdir, icon))
            continue
        if not (p.stat().st_mode & 0o111):
            continue
        if _is_elf(p) or _is_script(p):
            candidates.append(AppCandidate(p, p.name, False, [str(p)], str(p.parent)))
    candidates.sort(key=lambda c: (c.is_desktop_entry, c.name.lower()))
    return candidates


def _ensure_executable(target: Path) -> Optional[str]:
    """Add the exec bit if missing. Returns an error message on failure."""
    if os.access(target, os.X_OK):
        return None
    try:
        target.chmod(target.stat().st_mode | 0o111)
        return None
    except OSError as exc:
        return f"Could not make '{target.name}' executable ({exc})."


def _resolve_executable(candidate: AppCandidate) -> Optional[str]:
    """Validate/resolve candidate.exec_argv[0]. Returns an error message or None."""
    exe = candidate.exec_argv[0] if candidate.exec_argv else ""
    if not exe:
        return "The launcher has no valid Exec command."
    exe_path = Path(exe)
    if not exe_path.is_absolute():
        # Relative Exec commands resolve against the launcher's directory.
        resolved = candidate.path.parent / exe_path
        if resolved.is_file():
            candidate.exec_argv[0] = str(resolved)
            exe_path = resolved
        elif os.sep not in exe and not exe.startswith("."):
            # Bare command name (e.g. `Exec=firefox %u`) — search PATH.
            found = shutil.which(exe)
            if found:
                candidate.exec_argv[0] = found
                exe_path = Path(found)
    target = Path(candidate.exec_argv[0])
    if target.is_file():
        return _ensure_executable(target)
    # Not found on disk: only acceptable if it is a bare command on PATH.
    if os.sep not in target.name and not target.is_absolute():
        if shutil.which(target.name):
            return None
        return (f"'{target.name}' is not installed on this system. The application "
                "may require additional dependencies.")
    return (f"'{target}' was not found. The application may need additional "
            "libraries or installation steps.")


def launch_application(candidate: AppCandidate) -> tuple[bool, str]:
    """Explicit user-triggered launch. argv list only — never a shell string."""
    if candidate.is_desktop_entry:
        err = _resolve_executable(candidate)
        if err:
            return False, err
        target = Path(candidate.exec_argv[0])
        if not candidate.workdir and target.is_file():
            candidate.workdir = str(target.parent)
    else:
        p = candidate.path.resolve()
        if not p.exists():
            return False, f"File not found: {p}"
        err = _ensure_executable(p)
        if err:
            return False, err
        candidate.exec_argv = [str(p)]
        candidate.workdir = str(p.parent)
    try:
        subprocess.Popen(candidate.exec_argv,
                         cwd=candidate.workdir or None,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        return True, ""
    except FileNotFoundError:
        return False, (f"'{candidate.exec_argv[0]}' was not found. The application may "
                       "need additional libraries or installation steps.")
    except PermissionError:
        return False, "Permission denied while launching the application."
    except OSError as exc:
        return False, f"Could not launch ({exc}). The application may be missing libraries."


def open_folder(path: str) -> tuple[bool, str]:
    """Open a folder with the system default handler (no hard-coded manager)."""
    if not os.path.isdir(path):
        return False, f"Folder does not exist: {path}"
    try:
        subprocess.Popen(["xdg-open", path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        return True, ""
    except OSError as exc:
        return False, f"Could not open the folder ({exc})."


# ============================================================
# Desktop shortcuts and desktop launchers
# ============================================================

APPS_DIR = Path.home() / ".local" / "share" / "applications"
DESKTOP_DIR = Path.home() / "Desktop"


def _escape(value: str) -> str:
    """Escape a desktop-entry string value (backslash sequences)."""
    return value.replace("\\", "\\\\").replace("\r", "\\r") \
                .replace("\n", "\\n").replace("\t", "\\t")


def _quote_exec(value: str) -> str:
    """Quote an Exec value per the Desktop Entry spec.

    Exec is parsed like a shell command line: an unquoted space starts a new
    argument, so a single path containing spaces must be quoted. Inside double
    quotes the spec requires backslash-escaping of '"', '`', '$' and '\\'.
    """
    body = value.replace("\\", "\\\\").replace('"', '\\"') \
                .replace("`", "\\`").replace("$", "\\$")
    return f'"{body}"'


def _sanitize_id(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9 _.-]", "_", name.strip()).strip() or "ExtractedApp"
    return clean.replace(" ", "-")


def _find_icon(app_dir: Path, app_name: str) -> str:
    for pattern in ("*.png", "*.svg", "*.xpm"):
        for icon in sorted(app_dir.glob(pattern)):
            if icon.stem.lower() in (app_name.lower(), "icon", "app", "logo"):
                return str(icon)
    return ""


def _write_desktop_file(target: Path, name: str, exe: Path, workdir: Path,
                        icon: str) -> None:
    if not exe.is_file():
        raise OSError(f"Executable not found: {exe}")
    lines = [
        "[Desktop Entry]", "Type=Application",
        f"Name={_escape(name.strip() or 'Extracted Application')}",
        f"Exec={_quote_exec(str(exe))}",
        f"Path={_escape(str(workdir))}",
        "Terminal=false", "Categories=Utility;",
    ]
    if icon:
        lines.append(f"Icon={_escape(icon)}")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    target.chmod(0o644)


def create_shortcut(candidate: AppCandidate) -> tuple[bool, str]:
    """Write a user-level menu entry to ~/.local/share/applications. No root."""
    try:
        if not candidate.is_desktop_entry and not candidate.path.resolve().is_file():
            return False, (f"The application '{candidate.name}' no longer exists on disk; "
                           "cannot create a shortcut for it.")
        APPS_DIR.mkdir(parents=True, exist_ok=True)
        desktop_file = APPS_DIR / f"{_sanitize_id(candidate.name)}.desktop"
        if desktop_file.exists():
            return False, (f"A launcher named '{desktop_file.name}' already exists. "
                           "Remove the old launcher first or rename the application.")
        if candidate.is_desktop_entry:
            shutil.copy2(candidate.path, desktop_file)
            desktop_file.chmod(0o644)
        else:
            exe = candidate.path.resolve()
            icon = candidate.icon or _find_icon(exe.parent, candidate.name)
            _write_desktop_file(desktop_file, candidate.name, exe, exe.parent, icon)
        return True, (f"Shortcut created: {desktop_file.name}. "
                      "Your menu may take a moment to refresh.")
    except OSError as exc:
        return False, f"Could not create the shortcut ({exc})."


def add_to_desktop(candidate: AppCandidate) -> tuple[bool, str]:
    """Create a launcher on ~/Desktop.

    Note: Cinnamon does not offer a supported programmatic API for adding a
    launcher to the *panel* (panels only accept user-managed applets). A
    desktop launcher plus a menu shortcut is the supported equivalent; the
    menu entry can then be pinned to the panel via the menu applet.
    """
    try:
        if not candidate.is_desktop_entry and not candidate.path.resolve().is_file():
            return False, (f"The application '{candidate.name}' no longer exists on disk; "
                           "cannot create a launcher for it.")
        DESKTOP_DIR.mkdir(parents=True, exist_ok=True)
        target = DESKTOP_DIR / f"{_sanitize_id(candidate.name)}.desktop"
        if target.exists():
            return False, (f"A desktop launcher named '{target.name}' already exists. "
                           "Remove it first or rename the application.")
        if candidate.is_desktop_entry:
            shutil.copy2(candidate.path, target)
        else:
            exe = candidate.path.resolve()
            icon = candidate.icon or _find_icon(exe.parent, candidate.name)
            _write_desktop_file(target, candidate.name, exe, exe.parent, icon)
        target.chmod(0o755)  # Cinnamon needs the exec bit to treat it as launchable
        # Mark trusted via GVFS metadata when gio is available (best effort).
        subprocess.Popen(["gio", "set", str(target), "metadata::trusted", "true"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True, (f"Launcher added to Desktop: {target.name}. If prompted, "
                      "right-click it once and choose 'Allow Launching'.")
    except OSError as exc:
        return False, f"Could not add the launcher to the Desktop ({exc})."


# ============================================================
# Main window
# ============================================================


def _card(title: str) -> tuple[QFrame, QVBoxLayout]:
    card = QFrame()
    card.setObjectName("Card")
    lay = QVBoxLayout(card)
    lay.setContentsMargins(16, 14, 16, 14)
    lay.setSpacing(10)
    t = QLabel(title)
    t.setObjectName("CardTitle")
    lay.addWidget(t)
    return card, lay


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(620, 660)
        self.resize(700, 740)
        self.setAcceptDrops(True)

        self._worker: Optional[ExtractWorker] = None
        self._candidates: list[AppCandidate] = []
        self._rejected_count = 0
        self._skipped_count = 0
        self._default_dest = str(Path.home() / "Extracted")

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_header())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        body_lay = QVBoxLayout(body)
        body_lay.setContentsMargins(20, 16, 20, 20)
        body_lay.setSpacing(14)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        body_lay.addWidget(self._build_archive_card())
        body_lay.addWidget(self._build_dest_card())
        body_lay.addWidget(self._build_action_card())
        body_lay.addWidget(self._build_progress_card())
        body_lay.addWidget(self._build_apps_card())
        body_lay.addStretch(1)

        self._set_status("Select an archive to begin.", "idle")
        self._drop_overlay = QLabel("Drop archive to select it")
        self._drop_overlay.setObjectName("DropOverlay")
        self._drop_overlay.setAlignment(Qt.AlignCenter)
        self._drop_overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._drop_overlay.hide()

    # ---- UI construction --------------------------------------------------

    def _build_header(self) -> QFrame:
        header = QFrame()
        header.setObjectName("HeaderFrame")
        header.setFixedHeight(64)
        h = QHBoxLayout(header)
        h.setContentsMargins(20, 8, 20, 8)
        icon = QLabel("▤")
        icon.setObjectName("HeaderIcon")
        col = QVBoxLayout()
        col.setSpacing(0)
        t = QLabel(APP_NAME)
        t.setObjectName("AppTitle")
        s = QLabel("Extract, manage, and launch your applications.")
        s.setObjectName("AppSubtitle")
        col.addWidget(t)
        col.addWidget(s)
        v = QLabel(f"v{APP_VERSION}")
        v.setObjectName("VersionLabel")
        h.addWidget(icon)
        h.addSpacing(10)
        h.addLayout(col)
        h.addStretch(1)
        h.addWidget(v, 0, Qt.AlignTop)
        return header

    def _build_archive_card(self) -> QFrame:
        card, lay = _card("Archive")
        row = QHBoxLayout()
        row.setSpacing(8)
        self.archive_edit = QLineEdit()
        self.archive_edit.setReadOnly(True)
        self.archive_edit.setPlaceholderText("Choose a .zip or .tar.* archive, or drag it here")
        self.browse_archive_btn = QPushButton("Browse…")
        self.browse_archive_btn.clicked.connect(self._browse_archive)
        row.addWidget(self.archive_edit, 1)
        row.addWidget(self.browse_archive_btn)
        lay.addLayout(row)
        hint = QLabel("Supported: " + ", ".join(SUPPORTED_EXTS))
        hint.setObjectName("CardHint")
        lay.addWidget(hint)
        return card

    def _build_dest_card(self) -> QFrame:
        card, lay = _card("Destination")
        row = QHBoxLayout()
        row.setSpacing(8)
        self.dest_edit = QLineEdit(self._default_dest)
        self.browse_dest_btn = QPushButton("Browse Folder…")
        self.browse_dest_btn.clicked.connect(self._browse_dest)
        row.addWidget(self.dest_edit, 1)
        row.addWidget(self.browse_dest_btn)
        lay.addLayout(row)
        self.open_after_check = QCheckBox("Open destination folder after extraction")
        self.open_after_check.setChecked(True)
        lay.addWidget(self.open_after_check)
        return card

    def _build_action_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        lay = QHBoxLayout(card)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(10)
        self.extract_btn = QPushButton("Extract Archive")
        self.extract_btn.setObjectName("PrimaryButton")
        self.extract_btn.clicked.connect(self._start_extraction)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("DangerButton")
        self.cancel_btn.setVisible(False)
        self.cancel_btn.clicked.connect(self._cancel_extraction)
        self.open_folder_btn = QPushButton("Open Extracted Folder")
        self.open_folder_btn.setEnabled(False)
        self.open_folder_btn.clicked.connect(self._open_dest_folder)
        lay.addWidget(self.extract_btn, 2)
        lay.addWidget(self.cancel_btn, 1)
        lay.addWidget(self.open_folder_btn, 1)
        return card

    def _build_progress_card(self) -> QFrame:
        card, lay = _card("Progress")
        self.operation_label = QLabel("Idle")
        self.operation_label.setObjectName("CardHint")
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("ProgressBar")
        self.progress_bar.setRange(0, 100)
        self.current_file_label = QLabel("")
        self.current_file_label.setObjectName("CardHint")
        self.count_label = QLabel("")
        self.count_label.setObjectName("CardHint")
        lay.addWidget(self.operation_label)
        lay.addWidget(self.progress_bar)
        row = QHBoxLayout()
        row.addWidget(self.current_file_label, 1)
        row.addWidget(self.count_label)
        lay.addLayout(row)
        self.status_label = QLabel("")
        self.status_label.setObjectName("StatusLabel")
        self.status_label.setProperty("state", "idle")
        self.status_label.setWordWrap(True)
        lay.addWidget(self.status_label)
        return card

    def _build_apps_card(self) -> QFrame:
        self.apps_card = QFrame()
        self.apps_card.setObjectName("Card")
        self.apps_card.setVisible(False)
        lay = QVBoxLayout(self.apps_card)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(10)
        t = QLabel("Detected Applications")
        t.setObjectName("CardTitle")
        lay.addWidget(t)
        self.app_list = QListWidget()
        self.app_list.setMaximumHeight(150)
        lay.addWidget(self.app_list)
        row = QHBoxLayout()
        row.setSpacing(8)
        self.launch_btn = QPushButton("Launch Application")
        self.launch_btn.clicked.connect(self._launch_selected)
        self.desktop_btn = QPushButton("Add to Desktop")
        self.desktop_btn.clicked.connect(self._add_to_desktop)
        self.shortcut_btn = QPushButton("Create Menu Shortcut")
        self.shortcut_btn.clicked.connect(self._create_shortcut)
        row.addWidget(self.launch_btn, 1)
        row.addWidget(self.desktop_btn, 1)
        row.addWidget(self.shortcut_btn, 1)
        lay.addLayout(row)
        hint = QLabel("Launch only applications you trust. Extracted apps may need "
                      "extra libraries or installation steps.")
        hint.setObjectName("CardHint")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        return self.apps_card

    # ---- helpers ------------------------------------------------------------

    def _set_status(self, text: str, state: str) -> None:
        self.status_label.setText(text)
        self.status_label.setProperty("state", state)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def _archive_path(self) -> Optional[Path]:
        text = self.archive_edit.text().strip()
        return Path(text) if text else None

    def _resize_overlay(self) -> None:
        self._drop_overlay.resize(self.centralWidget().width() - 40, 80)
        self._drop_overlay.move(20, 80)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._resize_overlay()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        """Never let the QThread be destroyed while it is still running."""
        worker = self._worker
        if worker is not None and worker.isRunning():
            worker.cancel()
            app = QApplication.instance()
            for _ in range(200):  # up to ~10 s
                if worker.wait(50):
                    break
                if app is not None:
                    app.processEvents()
            if worker.isRunning():
                event.ignore()
                self._set_status("Extraction is still finishing; try closing again "
                                 "in a moment.", "warn")
                return
        event.accept()

    # ---- selection / drag & drop ---------------------------------------------

    def _browse_archive(self) -> None:
        filters = "Archives (" + " ".join("*" + e for e in SUPPORTED_EXTS) + ")"
        path, _ = QFileDialog.getOpenFileName(self, "Select Archive", str(Path.home()), filters)
        if path:
            self._set_archive(path)

    def _browse_dest(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Destination", self.dest_edit.text())
        if path:
            self.dest_edit.setText(path)

    def _set_archive(self, path: str) -> None:
        if not archive_kind(path):
            self._set_status(
                f"Unsupported file: {Path(path).name}. Supported: " + ", ".join(SUPPORTED_EXTS),
                "error")
            return
        if not os.path.isfile(path):
            self._set_status("The selected file does not exist.", "error")
            return
        self.archive_edit.setText(path)
        self._set_status("Archive selected. Choose a destination and click Extract.", "idle")

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._resize_overlay()
            self._drop_overlay.show()

    def dragLeaveEvent(self, event) -> None:  # noqa: N802
        self._drop_overlay.hide()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        self._drop_overlay.hide()
        urls = event.mimeData().urls()
        if urls:
            self._set_archive(urls[0].toLocalFile())

    # ---- extraction -------------------------------------------------------------

    def _validate_inputs(self) -> Optional[str]:
        arc = self._archive_path()
        if arc is None:
            return "No archive selected. Choose an archive file first."
        if not archive_kind(str(arc)):
            return "Unsupported archive format. Supported: " + ", ".join(SUPPORTED_EXTS)
        if not arc.is_file():
            return "The selected archive file could not be found."
        dest_text = self.dest_edit.text().strip()      # validate BEFORE Path()
        if not dest_text:
            return "No destination folder specified."
        dest = Path(os.path.expanduser(dest_text))     # expand '~'
        if not str(dest).strip():
            return "No destination folder specified."
        try:
            dest.mkdir(parents=True, exist_ok=True)
            if not dest.is_dir():
                return f"Destination is not a directory: {dest}"
            probe = dest / ".write_test"
            probe.write_bytes(b"")
            probe.unlink()
        except PermissionError:
            return "Permission denied: you cannot write to the destination folder."
        except OSError as exc:
            return f"Invalid destination: {exc}"
        return None

    def _set_ui_busy(self, busy: bool) -> None:
        self.extract_btn.setEnabled(not busy)
        self.cancel_btn.setVisible(busy)
        self.archive_edit.setEnabled(not busy)
        self.browse_archive_btn.setEnabled(not busy)
        self.dest_edit.setEnabled(not busy)
        self.browse_dest_btn.setEnabled(not busy)
        if busy:
            self.open_folder_btn.setEnabled(False)

    def _start_extraction(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return  # prevent duplicate jobs
        error = self._validate_inputs()
        if error:
            self._set_status(error, "error")
            return
        self._rejected_count = 0
        self._skipped_count = 0
        self.apps_card.setVisible(False)
        self._set_ui_busy(True)
        self._set_status("Extracting…", "idle")
        self.operation_label.setText("Extracting archive")
        self.progress_bar.setRange(0, 0)  # indeterminate until totals known

        self._worker = ExtractWorker(self.archive_edit.text(), self.dest_edit.text(), self)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_ok.connect(self._on_success)
        self._worker.failed.connect(self._on_failure)
        self._worker.rejected_entries.connect(self._on_rejected)
        self._worker.skipped_existing.connect(self._on_skipped)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    def _cancel_extraction(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self._set_status("Cancelling…", "warn")

    def _on_progress(self, current: str, done: int, total: int, determinate: bool) -> None:
        if determinate:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(int(done * 100 / total) if total else 0)
            self.count_label.setText(f"{done} / {total} files")
        self.current_file_label.setText(Path(current).name if current else "")

    def _on_rejected(self, count: int) -> None:
        self._rejected_count = count

    def _on_skipped(self, count: int) -> None:
        self._skipped_count = count

    def _final_message(self) -> tuple[str, str]:
        """Compose the completion message from reject/skip counts."""
        parts: list[str] = []
        state = "ok"
        if self._rejected_count:
            parts.append(f"{self._rejected_count} unsafe or unsupported archive "
                         f"{'entry was' if self._rejected_count == 1 else 'entries were'} "
                         "skipped for security reasons.")
            state = "warn"
        if self._skipped_count:
            parts.append(f"{self._skipped_count} existing "
                         f"{'file was' if self._skipped_count == 1 else 'files were'} "
                         "left unchanged (no overwrite).")
            state = "warn"
        base = "Extraction completed successfully."
        if parts:
            base = "Extraction completed; " + " ".join(parts)
        return base, state

    def _on_success(self, dest: str) -> None:
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.operation_label.setText("Completed")
        self.current_file_label.setText("")
        files = list(self._worker.recent_files) if self._worker else []
        self._show_candidates(detect_applications(files))
        base, state = self._final_message()
        if self._candidates:
            self._set_status(base, state)
        else:
            self._set_status(
                base + " No launchable application was detected. "
                "You can still open the extracted folder.", state)
        self.open_folder_btn.setEnabled(True)
        if self.open_after_check.isChecked():
            ok, err = open_folder(dest)
            if not ok:
                self._set_status("Extraction completed, but the folder could not be opened: "
                                 + err, "warn")

    def _on_failure(self, friendly: str, technical: str) -> None:
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.operation_label.setText("Failed")
        self.current_file_label.setText("")
        self.count_label.setText("")
        self._set_status(friendly, "error")
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle("Extraction Error")
        msg.setText(friendly)
        msg.setDetailedText(technical)  # technical details hidden by default
        msg.exec()

    def _on_worker_finished(self) -> None:
        """Restore state once the QThread truly finished (safe cleanup).

        Uses self.sender() so a replaced worker object can never be confused
        with the one that emitted this signal.
        """
        worker = self.sender()
        if worker is self._worker:
            self._worker = None
        self._set_ui_busy(False)

    def _open_dest_folder(self) -> None:
        ok, err = open_folder(self.dest_edit.text().strip())
        if not ok:
            self._set_status(err, "error")

    # ---- applications ----------------------------------------------------------

    def _show_candidates(self, candidates: list[AppCandidate]) -> None:
        self._candidates = candidates
        if not candidates:
            self.apps_card.setVisible(False)
            return
        self.apps_card.setVisible(True)
        self.app_list.clear()
        for c in candidates:
            item = QListWidgetItem(f"{'📄' if c.is_desktop_entry else '⚙'}  {c.name}")
            item.setData(Qt.UserRole, c)
            item.setToolTip(str(c.path))
            self.app_list.addItem(item)
        self.app_list.setCurrentRow(0)

    def _selected_candidate(self) -> Optional[AppCandidate]:
        item = self.app_list.currentItem()
        return item.data(Qt.UserRole) if item else None

    def _launch_selected(self) -> None:
        c = self._selected_candidate()
        if c is None:
            return
        ok, err = launch_application(c)
        self._set_status(f"Launched {c.name}." if ok else err, "ok" if ok else "error")

    def _add_to_desktop(self) -> None:
        c = self._selected_candidate()
        if c is None:
            return
        ok, msg = add_to_desktop(c)
        self._set_status(msg, "ok" if ok else "error")

    def _create_shortcut(self) -> None:
        c = self._selected_candidate()
        if c is None:
            return
        ok, msg = create_shortcut(c)
        self._set_status(msg, "ok" if ok else "error")


# ============================================================
# Entry point
# ============================================================


def main() -> int:
    
    
    
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("my_icon.ico"))
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setStyleSheet(STYLESHEET)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())


    