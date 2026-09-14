# AGENTS.md - Malicious Commit Dataset Reference

## Project Context
This repository contains the **Project Blackjack malicious-commit dataset**, which includes 28 red-team implant-corpus repositories represented as 29 cases. A case is the unit of evaluation because one repository can contain more than one independent implant campaign.

### Purpose
The dataset is designed for evaluating the performance of models or tools in detecting malicious commits in real-world scenarios. It provides ground truth labels and detailed information about commits, repositories, and malicious files.

## Key Datasets

### `malicious_commit_dataset_fixed` (Recommended)
This directory contains the corrected version of the dataset. The original dataset (`malicious_commit_dataset_obsolete`) had incorrect SHAs, which were fixed using the `fix_shas.py` script.

#### Files in `malicious_commit_dataset_fixed`:
- **`repositories.csv`**: Contains one row per corpus repository.
  - Row count: 28
  - SHA-256: `c7b5bfabae78a69393fcae7fe743772731c519c1d8cc7242e9ee91590d789189`

- **`cases.csv`**: Includes base, range tip, source, and malicious SHA summary per implant case.
  - Row count: 29
  - SHA-256: `1de640c2420adf9078ad2aa7915ed414055eb81a00246b6382433ba01ff2e6cd`

- **`commits.csv`**: Contains every commit in every test range, with binary malicious labels.
  - Row count: 862
  - SHA-256: `789a8387b4652701b2bb5e541a4ebda013b8e527ec08f87d97c0c699c6b0e195`

- **`malicious_files.csv`**: Lists files changed by malicious commits.
  - Row count: 124
  - SHA-256: `5624d477ec1c344ace5da4f4cc67b04a04831a821c745280208a56e36cdfaceb`

- **`cases.jsonl`**: Nested, model/evaluation-friendly representation including the full commit range and malicious file lists.
  - Row count: N/A (JSON Lines format)
  - SHA-256: `ca38df8fb542d58e0c356aa471a27f0051598928e5663ab85974ce9247eec991`

- **`manifest.json`**: Contains row totals and SHA-256 checksums for validation.

- **`validation_report.json`**: Provides detailed validation checks and status for each case.

### `malicious_commit_dataset_obsolete` (Deprecated)
This directory contains the original dataset with incorrect SHAs. It is obsolete and should not be used for analysis or evaluation. It is retained for historical reference only.

## Tools and Scripts

### `fix_shas.py`
This script corrects the SHA values in the dataset to point to the real commits in the upstream repositories.

#### Usage:
```bash
python fix_shas.py <dataset_dir> <fixed_dir> <tmp_repos>
```

#### How It Works:
1. **Argument Handling**: Takes three arguments:
   - `dataset_dir`: Path to the original dataset (e.g., `malicious_commit_dataset_obsolete`).
   - `fixed_dir`: Path where the corrected dataset will be written.
   - `tmp_repos`: Path to a temporary directory where repositories are cloned for SHA resolution.

2. **SHA Resolution**: The script resolves commit SHAs by matching commit subjects and author dates in the repository history. It ensures that the corrected SHAs point to the actual commits present in the upstream repositories.

3. **File Processing**: The script updates:
   - `commits.csv`: Corrects SHAs for all commits and updates related fields like `parent_shas`.
   - `malicious_files.csv`: Updates SHAs for malicious files.
   - `cases.csv`: Replaces SHA values and synchronizes range boundaries.

4. **Output**: The corrected dataset is written to `fixed_dir`, and static files are copied unchanged.

## Usage Instructions

### Recommended Evaluation Process
1. **Checkout the Base**: For each ready case, check out the `last_benign_sha`.
2. **Review the Range**: Review the commits in the `range_revspec`.
3. **Compare Predictions**: Compare model predictions against the `canonical_malicious_shas`.
4. **Report Metrics**: Report commit-level precision/recall and full-campaign detection. Do not count a multi-commit campaign as fully detected solely because one malicious commit was found.

### Example Workflow
1. Navigate to the corrected dataset:
   ```bash
   cd malicious_commit_dataset_fixed
   ```

2. Review `cases.csv` to identify the case you want to evaluate.

3. Use Git to check out the `last_benign_sha` for the case and review the commit range.

4. Validate model predictions against the dataset's ground truth labels.

## Issues and Fixes Applied

### Original Dataset Issues
- **Incorrect SHAs**: The original dataset (`malicious_commit_dataset_obsolete`) contained incorrect SHAs for commits and files. These SHAs did not point to the actual commits in the upstream repositories.

### Fixes Applied
- **SHA Resolution**: The `fix_shas.py` script was used to resolve and correct the SHAs. It matched commit subjects and author dates in the repository history to identify the correct SHAs.
- **Validation**: The corrected dataset (`malicious_commit_dataset_fixed`) has undergone validation to ensure that:
  - The SHAs in the dataset point to actual commits.
  - The commit ranges and malicious labels are accurate.
  - The dataset passes all validation checks (see `validation_report.json`).

## Validation Details

### Totals
- **Repositories**: 28
- **Cases**: 29
- **Commit Rows**: 862
- **Malicious Commit Rows**: 61
- **Malicious File Rows**: 124

### Validation Status
- **All Checks Passed**: The dataset has been validated, and all checks have passed. See `validation_report.json` for detailed validation results.

### Checks Per Case
Each case in the dataset has been validated for:
- **Range Exact**: The observed commit range matches the expected range.
- **Base Ancestor**: The last benign commit is an ancestor of the tip.
- **Malicious Count**: The observed number of malicious commits matches the expected count.
- **Canonical Labels in Range**: The number of canonical malicious labels in the range matches expectations.

## Fixes Applied

### SHA Resolution
- **Commit Resolution**: The `fix_shas.py` script resolved commit SHAs by matching commit subjects and author dates in the repository history. This ensured that the corrected SHAs point to the actual commits present in the upstream repositories.

### File Updates
- **commits.csv**: Corrected SHAs for all commits and updated related fields like `parent_shas`.
- **malicious_files.csv**: Updated SHAs for malicious files.
- **cases.csv**: Replaced SHA values and synchronized range boundaries.

## Final Notes
- **Use `malicious_commit_dataset_fixed`**: Always use the corrected dataset for accurate evaluation and analysis.
- **Avoid `malicious_commit_dataset_obsolete`**: The original dataset contains incorrect SHAs and should not be used.
- **Refer to Validation Report**: Review `validation_report.json` for detailed validation checks and status.
