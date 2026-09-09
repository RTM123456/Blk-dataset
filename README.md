# Malicious Commit Dataset

The repository contains two versions of the Blackjack malicious‑commit dataset:

- **`malicious_commit_dataset_og`** – the original release, which includes commit SHA identifiers that are incorrect.
- **`malicious_commit_dataset_fixed`** – the cleaned version where those SHA values have been corrected.

All other data files (cases, commits, manifests, etc.) are the same, but the fixed CSVs reflect the proper commit history for accurate evaluation.

## Fixing SHA identifiers

The `fix_shas.py` script was used to correct the erroneous SHA values in the original dataset. It reads the original CSV files, maps the incorrect SHAs to their corrected counterparts, and writes the updated files into the `malicious_commit_dataset_fixed` directory.

