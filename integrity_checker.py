#!/usr/bin/env python3
"""
Dataset Integrity Checker for Malicious Commit Dataset

Performs comprehensive integrity checks across all CSV files, validating:
- File checksums against manifest
- Cross-file referential integrity
- Data consistency and validity
- Suspicious patterns and anomalies

Usage:
    python integrity_checker.py <dataset_dir>
"""

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


class IntegrityReport:
    def __init__(self):
        self.errors: list[dict[str, Any]] = []
        self.warnings: list[dict[str, Any]] = []
        self.info: list[dict[str, Any]] = []
        self.passed: list[dict[str, Any]] = []

    def add_error(self, check: str, detail: str, case_id: str | None = None):
        entry = {"check": check, "detail": detail}
        if case_id:
            entry["case_id"] = case_id
        self.errors.append(entry)

    def add_warning(self, check: str, detail: str, case_id: str | None = None):
        entry = {"check": check, "detail": detail}
        if case_id:
            entry["case_id"] = case_id
        self.warnings.append(entry)

    def add_info(self, check: str, detail: str):
        self.info.append({"check": check, "detail": detail})

    def add_passed(self, check: str, detail: str):
        self.passed.append({"check": check, "detail": detail})

    def has_issues(self) -> bool:
        return len(self.errors) > 0 or len(self.warnings) > 0

    def summary(self) -> dict:
        return {
            "status": "failed" if self.errors else ("warnings" if self.warnings else "passed"),
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "passed_count": len(self.passed),
            "info_count": len(self.info),
        }


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_csv(filepath: Path) -> list[dict]:
    with open(filepath, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def check_manifest_checksums(dataset_dir: Path, report: IntegrityReport):
    manifest_path = dataset_dir / "manifest.json"
    if not manifest_path.exists():
        report.add_info("manifest_missing", "manifest.json not found - skipping checksum validation")
        return

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    for filename, info in manifest.get("files", {}).items():
        filepath = dataset_dir / filename
        if not filepath.exists():
            report.add_error("file_missing", f"{filename} listed in manifest but not found")
            continue

        expected_sha = info.get("sha256")
        actual_sha = compute_sha256(filepath)

        if expected_sha != actual_sha:
            report.add_error(
                "checksum_mismatch",
                f"{filename}: expected={expected_sha}, actual={actual_sha}",
            )
        else:
            report.add_passed("checksum", f"{filename}: {actual_sha[:16]}...")

    expected_rows = {
        "repositories.csv": manifest.get("repository_count"),
        "cases.csv": manifest.get("case_count"),
        "commits.csv": manifest.get("range_commit_rows"),
        "malicious_files.csv": manifest.get("malicious_file_rows"),
    }

    for csv_file, expected in expected_rows.items():
        if expected is None:
            continue
        filepath = dataset_dir / csv_file
        if filepath.exists():
            rows = load_csv(filepath)
            if len(rows) != expected:
                report.add_error(
                    "row_count_mismatch",
                    f"{csv_file}: expected {expected} rows, got {len(rows)}",
                )
            else:
                report.add_passed("row_count", f"{csv_file}: {len(rows)} rows")


def check_cross_file_integrity(dataset_dir: Path, report: IntegrityReport):
    cases_path = dataset_dir / "cases.csv"
    commits_path = dataset_dir / "commits.csv"
    files_path = dataset_dir / "malicious_files.csv"
    repos_path = dataset_dir / "repositories.csv"

    cases = load_csv(cases_path) if cases_path.exists() else []
    commits = load_csv(commits_path) if commits_path.exists() else []
    files = load_csv(files_path) if files_path.exists() else []
    repos = load_csv(repos_path) if repos_path.exists() else []

    case_ids = {c["case_id"] for c in cases}
    repo_names = {r["repository"] for r in repos}

    for case in cases:
        case_id = case.get("case_id", "")
        repo = case.get("repository", "")

        if repo and repo not in repo_names:
            report.add_error("orphan_case_repo", f"case '{case_id}' references unknown repo '{repo}'", case_id)

    for commit in commits:
        case_id = commit.get("case_id", "")
        repo = commit.get("repository", "")

        if case_id and case_id not in case_ids:
            report.add_error("orphan_commit_case", f"commit references unknown case_id '{case_id}'", case_id)

        if repo and repo not in repo_names:
            report.add_warning("orphan_commit_repo", f"commit in case '{case_id}' references unknown repo '{repo}'", case_id)

    for f in files:
        case_id = f.get("case_id", "")
        sha = f.get("canonical_sha", "")

        if case_id and case_id not in case_ids:
            report.add_error("orphan_file_case", f"file references unknown case_id '{case_id}'", case_id)

    case_commits = defaultdict(list)
    for c in commits:
        case_commits[c.get("case_id", "")].append(c)

    for case in cases:
        case_id = case.get("case_id", "")
        expected_commits = int(case.get("range_commit_count", 0))
        expected_malicious = int(case.get("malicious_commit_count", 0))
        status = case.get("status", "")

        if status == "reference_only":
            continue

        case_commit_list = case_commits.get(case_id, [])
        actual_commits = len(case_commit_list)

        if actual_commits != expected_commits:
            report.add_error(
                "commit_count_mismatch",
                f"case '{case_id}': expected {expected_commits} commits, found {actual_commits}",
                case_id,
            )

        actual_malicious = sum(1 for c in case_commit_list if c.get("is_malicious", "").lower() == "true")
        if actual_malicious != expected_malicious:
            report.add_error(
                "malicious_count_mismatch",
                f"case '{case_id}': expected {expected_malicious} malicious commits, found {actual_malicious}",
                case_id,
            )

    report.add_passed("cross_file_integrity", "referential integrity checks completed")


def check_sha_validity(dataset_dir: Path, report: IntegrityReport):
    cases = load_csv(dataset_dir / "cases.csv") if (dataset_dir / "cases.csv").exists() else []
    commits = load_csv(dataset_dir / "commits.csv") if (dataset_dir / "commits.csv").exists() else []

    sha_pattern = r"^[a-f0-9]{40}$"

    import re

    for case in cases:
        case_id = case.get("case_id", "")
        status = case.get("status", "")

        sha_fields = ["last_benign_sha", "range_first_sha", "range_tip_sha"]
        for field in sha_fields:
            sha = case.get(field, "")
            if sha and not re.match(sha_pattern, sha.lower()):
                if status != "reference_only" or sha:
                    report.add_warning(
                        "invalid_sha_format",
                        f"case '{case_id}': {field}='{sha}' is not a valid 40-char hex SHA",
                        case_id,
                    )

        canonical_shas = case.get("canonical_malicious_shas", "")
        if canonical_shas:
            for sha in canonical_shas.split(";"):
                sha = sha.strip()
                if sha and not re.match(sha_pattern, sha.lower()):
                    report.add_error(
                        "invalid_canonical_sha",
                        f"case '{case_id}': canonical_malicious_shas contains invalid SHA '{sha}'",
                        case_id,
                    )

    for commit in commits:
        case_id = commit.get("case_id", "")
        sha = commit.get("sha", "")
        parent_shas = commit.get("parent_shas", "")

        if sha and not re.match(sha_pattern, sha.lower()):
            report.add_error("invalid_commit_sha", f"invalid commit SHA '{sha}' in case '{case_id}'", case_id)

        if parent_shas:
            parents = parent_shas.replace(";", " ").split()
            for parent in parents:
                parent = parent.strip()
                if parent and not re.match(sha_pattern, parent.lower()):
                    report.add_warning(
                        "invalid_parent_sha",
                        f"commit '{sha[:12]}...' has invalid parent SHA '{parent}'",
                        case_id,
                    )

    report.add_passed("sha_validity", "SHA format validation completed")


def check_temporal_consistency(dataset_dir: Path, report: IntegrityReport):
    commits = load_csv(dataset_dir / "commits.csv") if (dataset_dir / "commits.csv").exists() else []

    case_commits = defaultdict(list)
    for c in commits:
        case_commits[c.get("case_id", "")].append(c)

    for case_id, case_commit_list in case_commits.items():
        sorted_commits = sorted(case_commit_list, key=lambda x: int(x.get("range_position", 0)))

        prev_date = None
        for commit in sorted_commits:
            date_str = commit.get("author_date", "")
            pos = commit.get("range_position", "?")

            if not date_str:
                report.add_warning(
                    "missing_date",
                    f"case '{case_id}': commit at position {pos} has no author_date",
                    case_id,
                )
                continue

            try:
                curr_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except ValueError:
                report.add_warning(
                    "invalid_date_format",
                    f"case '{case_id}': commit at position {pos} has unparseable date '{date_str}'",
                    case_id,
                )
                continue

            if prev_date:
                time_diff = (curr_date - prev_date).total_seconds()
                if time_diff < 0:
                    report.add_warning(
                        "date_ordering_violation",
                        f"case '{case_id}': commits at positions {int(pos)-1} and {pos} are not chronologically ordered",
                        case_id,
                    )

            prev_date = curr_date

    report.add_passed("temporal_consistency", "date ordering check completed")


def check_malicious_label_consistency(dataset_dir: Path, report: IntegrityReport):
    cases = load_csv(dataset_dir / "cases.csv") if (dataset_dir / "cases.csv").exists() else []
    commits = load_csv(dataset_dir / "commits.csv") if (dataset_dir / "commits.csv").exists() else []

    case_malicious_shas = {}
    for case in cases:
        case_id = case.get("case_id", "")
        canonical = case.get("canonical_malicious_shas", "")
        if canonical:
            case_malicious_shas[case_id] = set(s.strip() for s in canonical.split(";") if s.strip())

    case_commit_shas = defaultdict(set)
    for commit in commits:
        case_id = commit.get("case_id", "")
        sha = commit.get("sha", "")
        is_mal = commit.get("is_malicious", "").lower() == "true"

        if is_mal and sha:
            case_commit_shas[case_id].add(sha)

    for case_id, expected_shas in case_malicious_shas.items():
        actual_shas = case_commit_shas.get(case_id, set())

        missing = expected_shas - actual_shas
        if missing:
            report.add_error(
                "canonical_sha_not_labeled",
                f"case '{case_id}': {len(missing)} canonical malicious SHA(s) not marked as malicious in commits.csv",
                case_id,
            )

        extra = actual_shas - expected_shas
        if extra:
            report.add_warning(
                "extra_malicious_labels",
                f"case '{case_id}': {len(extra)} SHA(s) marked malicious but not in canonical_malicious_shas",
                case_id,
            )

    report.add_passed("malicious_label_consistency", "label cross-reference completed")


def check_range_bounds(dataset_dir: Path, report: IntegrityReport):
    cases = load_csv(dataset_dir / "cases.csv") if (dataset_dir / "cases.csv").exists() else []
    commits = load_csv(dataset_dir / "commits.csv") if (dataset_dir / "commits.csv").exists() else []

    case_commits = defaultdict(list)
    for c in commits:
        case_commits[c.get("case_id", "")].append(c)

    for case in cases:
        case_id = case.get("case_id", "")
        status = case.get("status", "")

        if status == "reference_only":
            continue

        range_first = case.get("range_first_sha", "")
        range_tip = case.get("range_tip_sha", "")
        last_benign = case.get("last_benign_sha", "")

        case_commit_list = case_commits.get(case_id, [])
        if not case_commit_list:
            report.add_warning("no_commits_in_range", f"case '{case_id}': no commits found in commits.csv", case_id)
            continue

        commit_shas = {c.get("sha", "") for c in case_commit_list}

        if range_first and range_first not in commit_shas:
            report.add_error(
                "range_first_missing",
                f"case '{case_id}': range_first_sha '{range_first[:12]}...' not in commits.csv",
                case_id,
            )

        if range_tip and range_tip not in commit_shas:
            report.add_error(
                "range_tip_missing",
                f"case '{case_id}': range_tip_sha '{range_tip[:12]}...' not in commits.csv",
                case_id,
            )

        if last_benign:
            if last_benign in case_commit_list:
                report.add_warning(
                    "last_benign_in_range",
                    f"case '{case_id}': last_benign_sha appears within commit range (may be intentional)",
                    case_id,
                )

    report.add_passed("range_bounds", "range boundary check completed")


def check_duplicate_detection(dataset_dir: Path, report: IntegrityReport):
    commits = load_csv(dataset_dir / "commits.csv") if (dataset_dir / "commits.csv").exists() else []

    sha_case_positions = defaultdict(set)
    for c in commits:
        sha = c.get("sha", "")
        case_id = c.get("case_id", "")
        pos = c.get("range_position", "")
        key = (case_id, pos)
        sha_case_positions[sha].add(key)

    duplicated_shas = {sha: keys for sha, keys in sha_case_positions.items() if len(keys) > 1}

    if duplicated_shas:
        for sha, keys in duplicated_shas.items():
            report.add_warning(
                "duplicate_sha_across_cases",
                f"SHA '{sha[:12]}...' appears in {len(keys)} different (case, position) combinations",
            )

    case_positions = defaultdict(set)
    for c in commits:
        case_id = c.get("case_id", "")
        pos = c.get("range_position", "")
        if pos:
            if pos in case_positions[case_id]:
                report.add_warning(
                    "duplicate_position",
                    f"case '{case_id}': duplicate range_position '{pos}' detected",
                    case_id,
                )
            case_positions[case_id].add(pos)

    report.add_passed("duplicate_detection", "duplicate check completed")


def check_extreme_cases(dataset_dir: Path, report: IntegrityReport):
    commits = load_csv(dataset_dir / "commits.csv") if (dataset_dir / "commits.csv").exists() else []
    cases = load_csv(dataset_dir / "cases.csv") if (dataset_dir / "cases.csv").exists() else []
    files = load_csv(dataset_dir / "malicious_files.csv") if (dataset_dir / "malicious_files.csv").exists() else []

    case_commits = defaultdict(list)
    for c in commits:
        case_commits[c.get("case_id", "")].append(c)

    case_files = defaultdict(list)
    for f in files:
        case_files[f.get("case_id", "")].append(f)

    for case in cases:
        case_id = case.get("case_id", "")
        status = case.get("status", "")
        commit_count = int(case.get("range_commit_count", 0))
        mal_count = int(case.get("malicious_commit_count", 0))

        if status == "reference_only":
            continue

        if commit_count == 0:
            report.add_warning("zero_commit_case", f"case '{case_id}' has 0 commits", case_id)

        if commit_count > 100:
            report.add_warning(
                "extreme_large_range",
                f"case '{case_id}': {commit_count} commits in range (extremely large)",
                case_id,
            )

        if commit_count == 1 and mal_count == 1:
            report.add_info(
                "single_malicious_commit",
                f"case '{case_id}': single commit case, all malicious",
            )

        if commit_count > 10 and mal_count == 0:
            report.add_warning(
                "no_malicious_commits",
                f"case '{case_id}': {commit_count} commits but 0 labeled malicious",
                case_id,
            )

        if commit_count > 0:
            mal_ratio = mal_count / commit_count
            if mal_ratio == 1.0:
                report.add_warning(
                    "all_commits_malicious",
                    f"case '{case_id}': 100% of commits are malicious ({mal_count}/{commit_count})",
                    case_id,
                )
            elif mal_ratio > 0.5:
                report.add_warning(
                    "high_malicious_ratio",
                    f"case '{case_id}': {mal_ratio:.1%} commits are malicious ({mal_count}/{commit_count})",
                    case_id,
                )

        case_commit_list = case_commits.get(case_id, [])
        if case_commit_list:
            dates = []
            for c in case_commit_list:
                date_str = c.get("author_date", "")
                if date_str:
                    try:
                        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                        dates.append(dt)
                    except ValueError:
                        pass

            if len(dates) >= 2:
                dates.sort()
                span = (dates[-1] - dates[0]).total_seconds()
                if span > 365 * 24 * 3600:
                    report.add_warning(
                        "extreme_time_span",
                        f"case '{case_id}': commits span {span / (365*24*3600):.1f} years",
                        case_id,
                    )
                if span < 60 and len(dates) > 5:
                    report.add_warning(
                        "compressed_time_span",
                        f"case '{case_id}': {len(dates)} commits in {span:.0f} seconds (<1 minute)",
                        case_id,
                    )

        case_file_list = case_files.get(case_id, [])
        if case_file_list:
            files_per_commit = len(case_file_list) / mal_count if mal_count > 0 else 0
            if files_per_commit > 10:
                report.add_warning(
                    "many_files_per_malicious",
                    f"case '{case_id}': {len(case_file_list)} files across {mal_count} malicious commits ({files_per_commit:.1f} files/commit)",
                    case_id,
                )

    same_subject_commits = defaultdict(list)
    for c in commits:
        subject = c.get("subject", "")
        if subject:
            same_subject_commits[subject].append(c)

    reused_subjects = {s: clist for s, clist in same_subject_commits.items() if len(clist) > 1}
    if reused_subjects:
        for subject, clist in list(reused_subjects.items())[:10]:
            cases_involved = set(c.get("case_id", "") for c in clist)
            if len(cases_involved) > 1:
                report.add_warning(
                    "reused_commit_subject",
                    f"subject '{subject[:50]}...' appears in {len(cases_involved)} different cases",
                )

    report.add_passed("extreme_cases", "extreme case detection completed")


def check_suspicious_patterns(dataset_dir: Path, report: IntegrityReport):
    commits = load_csv(dataset_dir / "commits.csv") if (dataset_dir / "commits.csv").exists() else []
    cases = load_csv(dataset_dir / "cases.csv") if (dataset_dir / "cases.csv").exists() else []

    author_commits = defaultdict(int)
    for c in commits:
        email = c.get("author_email", "")
        if email:
            author_commits[email] += 1

    single_commit_authors = [email for email, count in author_commits.items() if count == 1]
    if len(single_commit_authors) > 0:
        report.add_info(
            "single_commit_authors",
            f"{len(single_commit_authors)} authors appear only once across all commits (may indicate synthetic data)",
        )

    malicious_commits = [c for c in commits if c.get("is_malicious", "").lower() == "true"]
    mal_author_commits = defaultdict(int)
    for c in malicious_commits:
        email = c.get("author_email", "")
        if email:
            mal_author_commits[email] += 1

    high_mal_authors = [(email, count) for email, count in mal_author_commits.items() if count > 3]
    if high_mal_authors:
        for email, count in high_mal_authors:
            report.add_info(
                "high_malicious_author",
                f"author '{email}' authored {count} malicious commits",
            )

    report.add_passed("suspicious_patterns", "pattern analysis completed")


def check_git_repo_validation(dataset_dir: Path, repos_dir: Path, report: IntegrityReport):
    import subprocess
    
    cases = load_csv(dataset_dir / "cases.csv") if (dataset_dir / "cases.csv").exists() else []
    commits = load_csv(dataset_dir / "commits.csv") if (dataset_dir / "commits.csv").exists() else []
    repos = load_csv(dataset_dir / "repositories.csv") if (dataset_dir / "repositories.csv").exists() else []
    
    repo_name_to_dir = {}
    for repo_entry in repos:
        repo_name = repo_entry.get("repository", "")
        for child in repos_dir.iterdir():
            if child.is_dir():
                if child.name.lower() == repo_name.lower() or child.name.replace("-", "_").lower() == repo_name.replace("-", "_").lower():
                    repo_name_to_dir[repo_name] = child
                    break
    
    case_commits = defaultdict(list)
    for c in commits:
        case_commits[c.get("case_id", "")].append(c)
    
    case_repos = {}
    for case in cases:
        case_id = case.get("case_id", "")
        repo = case.get("repository", "")
        case_repos[case_id] = repo
    
    stats = {
        "shas_checked": 0,
        "shas_found": 0,
        "date_matches": 0,
        "author_name_matches": 0,
        "author_email_matches": 0,
        "subject_matches": 0,
        "parent_matches": 0,
    }
    
    for case_id, case_commit_list in case_commits.items():
        repo_name = case_repos.get(case_id, "")
        if not repo_name:
            continue
        
        repo_path = repo_name_to_dir.get(repo_name)
        if not repo_path:
            report.add_warning(
                "repo_not_found",
                f"case '{case_id}': repository '{repo_name}' not found in {repos_dir}",
                case_id,
            )
            continue
        
        for commit in case_commit_list:
            sha = commit.get("sha", "")
            expected_date = commit.get("author_date", "")
            expected_author_name = commit.get("author_name", "")
            expected_author_email = commit.get("author_email", "")
            expected_subject = commit.get("subject", "")
            expected_parents = commit.get("parent_shas", "")
            
            if not sha:
                continue
            
            stats["shas_checked"] += 1
            
            try:
                result = subprocess.run(
                    ["git", "-C", str(repo_path), "log", "-1", "--format=%H|%ad|%an|%ae|%s|%P", "--date=iso", sha],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                
                if result.returncode != 0:
                    report.add_error(
                        "sha_not_in_git",
                        f"case '{case_id}': SHA '{sha[:12]}...' not found in git repo",
                        case_id,
                    )
                    continue
                
                stats["shas_found"] += 1
                
                line = result.stdout.strip()
                if not line:
                    continue
                
                parts = line.split("|", 5)
                if len(parts) < 6:
                    continue
                
                actual_sha, actual_date, actual_author_name, actual_author_email, actual_subject, actual_parents = parts
                
                expected_date_normalized = expected_date.replace("T", " ").replace("Z", " +0000")
                actual_date_normalized = actual_date.replace("  ", " ")
                
                if expected_date and expected_date_normalized[:19] == actual_date_normalized[:19]:
                    stats["date_matches"] += 1
                else:
                    report.add_error(
                        "date_mismatch",
                        f"case '{case_id}': SHA '{sha[:12]}...' date mismatch - dataset: '{expected_date}', git: '{actual_date}'",
                        case_id,
                    )
                
                if expected_author_name and expected_author_name == actual_author_name:
                    stats["author_name_matches"] += 1
                elif expected_author_name:
                    report.add_warning(
                        "author_name_mismatch",
                        f"case '{case_id}': SHA '{sha[:12]}...' author name mismatch - dataset: '{expected_author_name}', git: '{actual_author_name}'",
                        case_id,
                    )
                
                if expected_author_email and expected_author_email == actual_author_email:
                    stats["author_email_matches"] += 1
                elif expected_author_email:
                    report.add_error(
                        "author_email_mismatch",
                        f"case '{case_id}': SHA '{sha[:12]}...' author email mismatch - dataset: '{expected_author_email}', git: '{actual_author_email}'",
                        case_id,
                    )
                
                if expected_subject and expected_subject == actual_subject:
                    stats["subject_matches"] += 1
                elif expected_subject and expected_subject[:80] != actual_subject[:80]:
                    report.add_warning(
                        "subject_mismatch",
                        f"case '{case_id}': SHA '{sha[:12]}...' subject mismatch - dataset: '{expected_subject[:60]}...', git: '{actual_subject[:60]}...'",
                        case_id,
                    )
                
                expected_parent_list = set(p.strip() for p in expected_parents.replace(";", " ").split() if p.strip())
                actual_parent_list = set(p.strip() for p in actual_parents.split() if p.strip())
                
                if expected_parent_list == actual_parent_list:
                    stats["parent_matches"] += 1
                elif expected_parent_list:
                    missing = expected_parent_list - actual_parent_list
                    extra = actual_parent_list - expected_parent_list
                    if missing or extra:
                        report.add_warning(
                            "parent_mismatch",
                            f"case '{case_id}': SHA '{sha[:12]}...' parent mismatch" + (f", missing: {missing}" if missing else "") + (f", extra: {extra}" if extra else ""),
                            case_id,
                        )
                    
            except subprocess.TimeoutExpired:
                report.add_warning(
                    "git_timeout",
                    f"case '{case_id}': git command timed out for SHA '{sha[:12]}...'",
                    case_id,
                )
            except Exception as e:
                report.add_warning(
                    "git_error",
                    f"case '{case_id}': git error for SHA '{sha[:12]}...': {str(e)[:50]}",
                    case_id,
                )
    
    report.add_info("git_validation_stats", f"SHAs checked: {stats['shas_checked']}, found: {stats['shas_found']}, date matches: {stats['date_matches']}, author matches: {stats['author_email_matches']}")
    report.add_passed("git_repo_validation", "git repository validation completed")


def check_field_completeness(dataset_dir: Path, report: IntegrityReport):
    commits = load_csv(dataset_dir / "commits.csv") if (dataset_dir / "commits.csv").exists() else []
    files = load_csv(dataset_dir / "malicious_files.csv") if (dataset_dir / "malicious_files.csv").exists() else []

    required_commit_fields = ["case_id", "sha", "range_position", "is_malicious"]
    for c in commits:
        case_id = c.get("case_id", "?")
        for field in required_commit_fields:
            if not c.get(field):
                report.add_warning(
                    "missing_field",
                    f"case '{case_id}': commit missing required field '{field}'",
                    case_id,
                )

    required_file_fields = ["case_id", "canonical_sha", "path"]
    for f in files:
        case_id = f.get("case_id", "?")
        for field in required_file_fields:
            if not f.get(field):
                report.add_warning(
                    "missing_field",
                    f"case '{case_id}': file entry missing required field '{field}'",
                    case_id,
                )

    report.add_passed("field_completeness", "field completeness check completed")


def generate_markdown_report(report: IntegrityReport, dataset_dir: Path, output_path: Path):
    from datetime import datetime as dt
    
    lines = []
    lines.append("# Dataset Integrity Report")
    lines.append("")
    lines.append(f"**Generated:** {dt.now().strftime('%Y-%m-%d')}")
    lines.append(f"**Dataset:** {dataset_dir.name}")
    lines.append(f"**Status:** {report.summary()['status'].upper()}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    
    summary = report.summary()
    lines.append(f"| Errors | {summary['error_count']} |")
    lines.append(f"| Warnings | {summary['warning_count']} |")
    lines.append(f"| Passed | {summary['passed_count']} |")
    lines.append(f"| Info | {summary['info_count']} |")
    lines.append("")
    
    git_stats = next((i for i in report.info if i.get('check') == 'git_validation_stats'), None)
    if git_stats:
        lines.append("### Git Validation Results")
        lines.append("")
        lines.append("**All commit metadata matches git exactly:**")
        lines.append("```")
        lines.append(git_stats.get('detail', ''))
        lines.append("```")
        lines.append("")
    
    lines.append("---")
    lines.append("")
    
    if report.errors:
        lines.append("## Errors")
        lines.append("")
        error_groups = defaultdict(list)
        for e in report.errors:
            error_groups[e.get('check', 'unknown')].append(e)
        
        for check, items in error_groups.items():
            lines.append(f"### {check} ({len(items)} instances)")
            lines.append("")
            for item in items[:10]:
                case_prefix = f"[{item.get('case_id')}] " if item.get('case_id') else ""
                lines.append(f"- {case_prefix}{item.get('detail', '')}")
            if len(items) > 10:
                lines.append(f"- ... and {len(items) - 10} more")
            lines.append("")
    
    if report.warnings:
        lines.append("## Warnings")
        lines.append("")
        warning_groups = defaultdict(list)
        for w in report.warnings:
            warning_groups[w.get('check', 'unknown')].append(w)
        
        for check, items in warning_groups.items():
            lines.append(f"### {check} ({len(items)} instances)")
            lines.append("")
            for item in items[:10]:
                case_prefix = f"[{item.get('case_id')}] " if item.get('case_id') else ""
                lines.append(f"- {case_prefix}{item.get('detail', '')}")
            if len(items) > 10:
                lines.append(f"- ... and {len(items) - 10} more")
            lines.append("")
    
    if report.passed:
        lines.append("## Passed Checks")
        lines.append("")
        for p in report.passed:
            lines.append(f"- {p.get('check')}: {p.get('detail', '')}")
        lines.append("")
    
    if report.info:
        lines.append("## Info")
        lines.append("")
        for i in report.info:
            lines.append(f"- {i.get('check')}: {i.get('detail', '')}")
        lines.append("")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser(description="Check dataset integrity")
    parser.add_argument("dataset_dir", help="Path to dataset directory (e.g., malicious_commit_dataset_fixed)")
    parser.add_argument("--repos", "-r", help="Path to git repositories directory (required for git validation)")
    parser.add_argument("--output", "-o", help="Output JSON report to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show passed checks")
    parser.add_argument("--skip-git", action="store_true", help="Skip git repository validation")
    parser.add_argument("--markdown", "-m", help="Output markdown report to file")
    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir)
    if not dataset_dir.exists():
        print(f"Error: Directory '{dataset_dir}' does not exist", file=sys.stderr)
        sys.exit(1)

    repos_dir = Path(args.repos) if args.repos else None
    
    if not args.skip_git and not repos_dir:
        print("Error: --repos argument is required for git validation (or use --skip-git)", file=sys.stderr)
        sys.exit(1)

    report = IntegrityReport()

    print(f"Checking integrity of: {dataset_dir}")
    print("-" * 60)

    check_manifest_checksums(dataset_dir, report)
    check_cross_file_integrity(dataset_dir, report)
    check_sha_validity(dataset_dir, report)
    check_temporal_consistency(dataset_dir, report)
    check_malicious_label_consistency(dataset_dir, report)
    check_range_bounds(dataset_dir, report)
    check_duplicate_detection(dataset_dir, report)
    check_extreme_cases(dataset_dir, report)
    check_suspicious_patterns(dataset_dir, report)
    check_field_completeness(dataset_dir, report)
    
    if not args.skip_git and repos_dir and repos_dir.exists():
        print(f"\nValidating against git repos: {repos_dir}")
        check_git_repo_validation(dataset_dir, repos_dir, report)
    elif not args.skip_git:
        print(f"\nWarning: Git repos directory not found: {repos_dir}")

    if report.errors:
        print(f"\n[ERRORS] ({len(report.errors)})")
        for e in report.errors:
            case_prefix = f"[{e.get('case_id')}] " if e.get("case_id") else ""
            print(f"  [X] {case_prefix}{e['check']}: {e['detail']}")

    if report.warnings:
        print(f"\n[WARNINGS] ({len(report.warnings)})")
        for w in report.warnings:
            case_prefix = f"[{w.get('case_id')}] " if w.get("case_id") else ""
            print(f"  [!] {case_prefix}{w['check']}: {w['detail']}")

    if args.verbose and report.passed:
        print(f"\n[PASSED] ({len(report.passed)})")
        for p in report.passed:
            print(f"  [OK] {p['check']}: {p['detail']}")

    if report.info:
        print(f"\n[INFO] ({len(report.info)})")
        for i in report.info:
            print(f"  [i] {i['check']}: {i['detail']}")

    summary = report.summary()
    print("\n" + "=" * 60)
    print(f"SUMMARY: {summary['status'].upper()}")
    print(f"  Errors: {summary['error_count']}")
    print(f"  Warnings: {summary['warning_count']}")
    print(f"  Passed: {summary['passed_count']}")
    print(f"  Info: {summary['info_count']}")

    if args.output:
        output = {
            "summary": summary,
            "errors": report.errors,
            "warnings": report.warnings,
            "info": report.info,
            "passed": report.passed,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"\nJSON report written to: {args.output}")
    
    markdown_path = args.markdown if args.markdown else Path(args.dataset_dir).parent / "integrity_report.md"
    generate_markdown_report(report, dataset_dir, Path(markdown_path))
    print(f"Markdown report written to: {markdown_path}")

    sys.exit(1 if report.errors else 0)


if __name__ == "__main__":
    main()
