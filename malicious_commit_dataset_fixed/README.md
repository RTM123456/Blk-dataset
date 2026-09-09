# Project Blackjack malicious-commit dataset

This dataset contains 28 red-team implant-corpus repositories represented as 29 cases.  A case is the unit of evaluation because one repository can contain more than one independent implant campaign.

## Semantics

- `last_benign_sha` is the exclusive base revision supplied to the model.
- `range_revspec` is the full candidate range (`last_benign_sha..range_tip_sha`).
- Every commit in that range appears in `commits.csv`; `is_malicious` is the answer-backed label.
- `answer_labeled_shas` preserves the identifiers written by the red team.
- `canonical_malicious_shas` contains the equivalent commits actually present in the review range.  They differ only where history rewriting changed commit identity; `patch_id` and `match_method` retain the mapping.
- `malicious_files.csv` distinguishes answer-identified implant paths from the broader fallback of all files touched by a malicious commit.  Neither is a line-level label.
- `new_features` is retained as `reference_only`: it is an answer catalog whose referenced Fleetbase histories are not present as local commits.  Its V4 case is represented by `Ori-Fleetbase-v4`.

## Files

- `repositories.csv`: one row per corpus repository.
- `cases.csv`: base, range tip, source, and malicious SHA summary per implant case.
- `commits.csv`: every commit in every test range, with the binary malicious label.
- `malicious_files.csv`: files changed by malicious commits.
- `cases.jsonl`: nested, model/evaluation-friendly representation including the full commit range and malicious file lists.
- `manifest.json`: row totals and SHA-256 checksums.

## Recommended evaluation

For each ready case, check out `last_benign_sha`, review the commits in `range_revspec`, and compare model predictions against `canonical_malicious_shas`.  Report commit-level precision/recall and full-campaign detection; do not count a multi-commit campaign as fully detected merely because one malicious commit was found.

Note: `malicious_commit_dataset_og` contains the original data with incorrect SHAs, while `malicious_commit_dataset_fixed` holds the corrected versions.
