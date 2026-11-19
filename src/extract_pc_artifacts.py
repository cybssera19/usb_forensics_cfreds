"""Export raw Dissect records, preserving commands and hashes.
Normalization into the correlation engine's schema requires a reviewed adapter.
"""
import argparse
import shutil
import subprocess
from pathlib import Path
from usb_forensics import sha256_file, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--plugins", nargs="+", default=["usb", "jumplist", "lnk", "usnjrnl", "evtx"])
    args = parser.parse_args()
    executable = shutil.which("target-query")
    if not executable:
        parser.error("Install Dissect dahulu: python -m pip install dissect")
    image = Path(args.image).resolve()
    if not image.is_file():
        parser.error("Image tidak ditemukan.")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    manifest = {"image": str(image), "image_sha256": sha256_file(image), "runs": [],
                "status": "raw_exports_require_review_and_normalization"}
    jobs = [("version", [executable, "--version"]),
            ("plugins", [executable, str(image), "-l"])]
    jobs += [("artifact-" + str(i), [executable, str(image), "-f", name, "-j"])
             for i, name in enumerate(args.plugins)]
    for label, command in jobs:
        raw, errors = out / (label + ".jsonl"), out / (label + ".stderr.txt")
        with raw.open("wb") as stdout, errors.open("wb") as stderr:
            process = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
        status = "raw_export_needs_review" if process.returncode == 0 else "failed"
        if process.returncode == 0 and raw.stat().st_size == 0:
            status = "empty_needs_review"
        manifest["runs"].append({
            "command": command, "returncode": process.returncode, "status": status,
            "output": str(raw), "output_sha256": sha256_file(raw),
            "stderr": str(errors)
        })
        write_json(out / "manifest.json", manifest)
    print(out / "manifest.json")


if __name__ == "__main__":
    main()
