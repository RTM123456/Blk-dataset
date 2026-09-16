# Malicious Commit Dataset

The repository contains two versions of the Blk malicious‑commit dataset:

- **`malicious_commit_dataset_og`** – the original release, which includes commit SHA identifiers that are incorrect.
- **`malicious_commit_dataset_fixed`** – the cleaned version where those SHA values have been corrected.

All other data files (cases, commits, manifests, etc.) are the same, but the fixed CSVs reflect the proper commit history for accurate evaluation.

## Fixing SHA identifiers

The `fix_shas.py` script was used to correct the erroneous SHA values in the original dataset. It reads the original CSV files, maps the incorrect SHAs to their corrected counterparts, and writes the updated files into the `malicious_commit_dataset_fixed` directory.

## Commit Ordering

**Important:** Commits in this dataset are ordered by **topological order** (git ancestry), not by author timestamp.

This means that commits may appear in an order that does not match their `author_date` values. This is expected behavior:

- Commits are ordered by parent-child relationships in the git history
- A commit authored earlier may appear later in the range if it was pushed or merged after later commits
- Multiple authors in different timezones can contribute to the same branch, resulting in non-chronological author dates
- This reflects real-world git behavior and should not be considered a data quality issue

For example, a commit authored at `2026-04-14 09:20:00` may appear after a commit authored at `2026-04-14 11:13:00` if the earlier-authored commit was pushed after the later one.

## Integrity Checking

Use `integrity_checker.py` to validate the dataset against the source git repositories:

```bash
python integrity_checker.py malicious_commit_dataset_fixed -r <path_to_repos>
```

This validates:
- All SHAs exist in the git repositories
- Author dates match git exactly
- Author emails match git exactly
- Commit subjects match git
- Parent SHAs match git
- Cross-file referential integrity
- Malicious label consistency

