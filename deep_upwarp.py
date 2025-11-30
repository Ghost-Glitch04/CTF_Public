#!/usr/bin/env python3
"""
Recursively unwrap gzip / bzip2 / tar layers in a file.

Usage examples:

    # Basic:
    python3 deep_unwrap.py data.bin

    # Also try to print any final text files (good for flags):
    python3 deep_unwrap.py data.bin --print-text
"""

import argparse
import bz2
import gzip
import os
import shutil
import sys
import tarfile
from collections import deque
from pathlib import Path


# ---------- Detection ----------

def detect_type(path: Path):
    """
    Detect whether file is gzip, bzip2, or tar.
    Returns one of: 'gzip', 'bzip2', 'tar', or None.
    """
    # Quick tar check first
    try:
        if tarfile.is_tarfile(path):
            return "tar"
    except Exception:
        pass

    # Magic byte checks
    with path.open("rb") as f:
        header = f.read(4)

    # gzip: 1F 8B
    if header.startswith(b"\x1f\x8b"):
        return "gzip"

    # bzip2: 'BZh'
    if header.startswith(b"BZh"):
        return "bzip2"

    return None


# ---------- Decompressors ----------

def decompress_gzip(path: Path, iteration: int) -> Path:
    out_path = path.with_suffix(path.suffix + f".ungz{iteration}")
    print(f"[+] GZIP  : {path} -> {out_path}")
    with gzip.open(path, "rb") as f_in, out_path.open("wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    return out_path


def decompress_bzip2(path: Path, iteration: int) -> Path:
    out_path = path.with_suffix(path.suffix + f".unbz2{iteration}")
    print(f"[+] BZIP2 : {path} -> {out_path}")
    with path.open("rb") as f_in, out_path.open("wb") as f_out:
        decompressor = bz2.BZ2Decompressor()
        for chunk in iter(lambda: f_in.read(1024 * 1024), b""):
            f_out.write(decompressor.decompress(chunk))
    return out_path


def extract_tar(path: Path, iteration: int) -> list[Path]:
    """
    Extract TAR archive into a directory.
    Returns a list of extracted regular files.
    """
    out_dir = path.parent / f"{path.stem}.tar_extract{iteration}"
    out_dir.mkdir(exist_ok=True)
    print(f"[+] TAR   : {path} -> {out_dir}")

    extracted_files = []

    with tarfile.open(path, "r:*") as tf:
        tf.extractall(path=out_dir)
        for member in tf.getmembers():
            if member.isfile():
                extracted_files.append(out_dir / member.name)

    if not extracted_files:
        print("[!] Tar contained no regular files.")

    return extracted_files


# ---------- Heuristics for final files ----------

def is_probably_text(path: Path, sample_size: int = 4096) -> bool:
    """
    Very rough heuristic: checks if most bytes are printable-ish.
    """
    try:
        data = path.read_bytes()[:sample_size]
    except Exception:
        return False

    if not data:
        return False

    # If it decodes cleanly as UTF-8, call it text.
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass

    # Fallback: check ratio of printable bytes
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    return printable / len(data) > 0.85


def print_file_if_text(path: Path):
    if not is_probably_text(path):
        return
    print(f"\n----- TEXT CANDIDATE: {path} -----")
    try:
        print(path.read_text(errors="replace"))
    except Exception as e:
        print(f"[!] Could not print {path}: {e}")
    print("----- END TEXT -----\n")


# ---------- Main unwrap logic ----------

def unwrap(start_file: Path, max_iterations: int = 100, print_text: bool = False):
    """
    Orchestrates recursive unwrap in a working directory.
    """
    start_file = start_file.resolve()

    # Working directory lives next to the input file
    workdir = start_file.parent / (start_file.name + ".unwrap")
    workdir.mkdir(exist_ok=True)

    # Copy the initial file into workdir as root.bin
    root = workdir / "root.bin"
    shutil.copy2(start_file, root)
    print(f"[*] Working directory: {workdir}")
    print(f"[*] Root file        : {root}")

    queue = deque([root])
    processed: set[Path] = set()
    final_files: set[Path] = set()
    iteration = 0

    while queue and iteration < max_iterations:
        current = queue.popleft()
        current = current.resolve()

        if current in processed or not current.is_file():
            continue

        processed.add(current)
        ftype = detect_type(current)
        print(f"[i] Iteration {iteration}: {current} -> {ftype}")

        if ftype == "gzip":
            new_file = decompress_gzip(current, iteration)
            queue.append(new_file)
        elif ftype == "bzip2":
            new_file = decompress_bzip2(current, iteration)
            queue.append(new_file)
        elif ftype == "tar":
            new_files = extract_tar(current, iteration)
            queue.extend(new_files)
        else:
            # Not a known archive type; treat as final
            final_files.add(current)

        iteration += 1

    if iteration >= max_iterations:
        print("[!] Reached max iteration limit; stopping.")

    # Report final non-archive files
    print("\n[*] Final non-archive files discovered:")
    if not final_files:
        print("    (none)")
    else:
        for f in sorted(final_files):
            print(f"    {f}")

    if print_text:
        for f in sorted(final_files):
            print_file_if_text(f)


def main():
    parser = argparse.ArgumentParser(
        description="Recursively unwrap gzip/bzip2/tar layers in a file."
    )
    parser.add_argument("file", help="Input file (binary, not hex dump)")
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=100,
        help="Safety limit for recursion (default: 100)",
    )
    parser.add_argument(
        "--print-text",
        action="store_true",
        help="Attempt to print final files that look like text (good for flags)",
    )
    args = parser.parse_args()

    start = Path(args.file)
    if not start.is_file():
        print(f"[!] Input file not found: {start}")
        sys.exit(1)

    unwrap(start, max_iterations=args.max_iterations, print_text=args.print_text)


if __name__ == "__main__":
    main()
