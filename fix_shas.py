#!/usr/bin/env python3
"""
fix_shas.py

Fixes all SHA values in the malicious‑commit dataset so they point at the real
commits in the upstream repos.

Usage:
    python fix_shas.py <dataset_dir> <fixed_dir> <tmp_repos>
"""

import csv, subprocess, pathlib, datetime, sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

# --------------------------------------------------------------------------- #
# 0️⃣  Argument handling
# --------------------------------------------------------------------------- #
if len(sys.argv) != 4:
    print("Usage: python fix_shas.py <dataset_dir> <fixed_dir> <tmp_repos>")
    sys.exit(1)

DATASET_DIR = pathlib.Path(sys.argv[1]).resolve()
FIXED_DIR   = pathlib.Path(sys.argv[2]).resolve()
TMP_REPOS   = pathlib.Path(sys.argv[3]).resolve()

# --------------------------------------------------------------------------- #
# 1️⃣  Helper utilities
# --------------------------------------------------------------------------- #
def read_csv(path: pathlib.Path):
    """Read a CSV file (UTF‑8, handles possible BOM)."""
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def write_csv(path: pathlib.Path, fieldnames, rows):
    """Write CSV (UTF‑8). Overwrites if the file already exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

def get_col(row, name):
    for k in row:
        if k.strip().lstrip("\ufeff").lower() == name.lower():
            return row[k]
    return row.get(name, "")

def run_git(repo: pathlib.Path, args):
    """Run a git command inside *repo* and return (stdout, returncode)."""
    cmd = ["git", "-C", str(repo)] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",   # replace undecodable bytes
    )
    return result.stdout, result.returncode

def parent_shas(repo: pathlib.Path, sha: str):
    """Return space‑separated parent SHAs for *sha* (empty string if none)."""
    stdout, rc = run_git(repo, ["rev-parse", f"{sha}^@"])
    if rc != 0:
        return ""   # root commit or error
    return stdout.strip()

def short_sha(sha: str) -> str:
    return sha[:12]


# Pre-cache git logs for fast, deterministic lookups
repo_head_logs = {}
repo_all_logs = {}

def get_repo_git_logs(repo_path: pathlib.Path):
    if repo_path in repo_head_logs:
        return repo_head_logs[repo_path], repo_all_logs[repo_path]
    
    # 1. HEAD log
    head_stdout, rc1 = run_git(repo_path, ["log", "HEAD", "--pretty=%H;%ad;%s", "--date=iso"])
    head_list = []
    if rc1 == 0:
        for line in head_stdout.splitlines():
            if ";" in line:
                parts = line.split(";", 2)
                head_list.append({"sha": parts[0], "date": parts[1], "subject": " ".join(parts[2].split())})
                
    # 2. ALL log
    all_stdout, rc2 = run_git(repo_path, ["log", "--all", "--pretty=%H;%ad;%s", "--date=iso"])
    all_list = []
    if rc2 == 0:
        for line in all_stdout.splitlines():
            if ";" in line:
                parts = line.split(";", 2)
                all_list.append({"sha": parts[0], "date": parts[1], "subject": " ".join(parts[2].split())})
                
    repo_head_logs[repo_path] = head_list
    repo_all_logs[repo_path] = all_list
    return head_list, all_list


def resolve_commit_sha(repo_path: pathlib.Path, subject: str, author_date: str, orig_sha: str) -> str:
    norm_subj = " ".join(subject.split())
    head_list, all_list = get_repo_git_logs(repo_path)

    # Step 1: HEAD review branch subject match
    head_matches = [c for c in head_list if c["subject"] == norm_subj]
    if len(head_matches) == 1:
        return head_matches[0]["sha"]
    elif len(head_matches) > 1 and author_date:
        date_matches = [c for c in head_matches if c["date"].startswith(author_date[:16])]
        if len(date_matches) == 1:
            return date_matches[0]["sha"]
        elif len(date_matches) > 1:
            head_matches = date_matches

    # Step 2: ALL branches subject match
    all_matches = [c for c in all_list if c["subject"] == norm_subj]
    if len(all_matches) == 1:
        return all_matches[0]["sha"]
    elif len(all_matches) > 1 and author_date:
        date_matches = [c for c in all_matches if c["date"].startswith(author_date[:16])]
        if len(date_matches) == 1:
            return date_matches[0]["sha"]
        elif len(date_matches) > 1:
            all_matches = date_matches

    # Fallback to candidates from HEAD or ALL
    pool = head_matches if head_matches else all_matches
    if pool:
        return pool[0]["sha"]

    print(f"⚠️  No commit match found for '{subject}'. Keeping original SHA: {orig_sha}")
    return orig_sha


# --------------------------------------------------------------------------- #
# 2️⃣  Build a repository‑name → local‑path map (BOM‑safe)
# --------------------------------------------------------------------------- #
repo_entries = read_csv(DATASET_DIR / "repositories.csv")
repo_path_map = {}
for rec in repo_entries:
    repo_name = get_col(rec, "repository")
    if not repo_name:
        raise KeyError("Could not find the 'repository' column in repositories.csv")
    repo_path_map[repo_name] = TMP_REPOS / repo_name

# --------------------------------------------------------------------------- #
# 3️⃣  Process commits.csv
# --------------------------------------------------------------------------- #
commits = read_csv(DATASET_DIR / "commits.csv")
new_commits = []
sha_map = {}   # original_sha → corrected_sha
case_commit_map = {} # case_id -> list of new_commit rows

print("\n=== Scanning commits.csv ===")
for idx, row in enumerate(commits, 1):
    repo_name = get_col(row, "repository")
    repo_path = repo_path_map[repo_name]
    subject = get_col(row, "subject")
    author_date = get_col(row, "author_date")
    orig_sha = get_col(row, "sha")
    cid = get_col(row, "case_id")

    new_sha = resolve_commit_sha(repo_path, subject, author_date, orig_sha)

    # ---- Record mapping & update row ----
    sha_map[orig_sha] = new_sha
    row["sha"] = new_sha
    row["short_sha"] = short_sha(new_sha)
    row["parent_shas"] = parent_shas(repo_path, new_sha)
    row["answer_sha_aliases"] = orig_sha   # keep original as alias
    new_commits.append(row)

    if cid not in case_commit_map:
        case_commit_map[cid] = []
    case_commit_map[cid].append(row)

print(f"\n✅  Processed {len(commits)} commit rows → {len(sha_map)} unique SHA mappings")


# --------------------------------------------------------------------------- #
# 4️⃣  Update malicious_files.csv
# --------------------------------------------------------------------------- #
mal_files = read_csv(DATASET_DIR / "malicious_files.csv")
new_mal_files = []

print("\n=== Updating malicious_files.csv ===")
for row in mal_files:
    orig = get_col(row, "canonical_sha")
    new = sha_map.get(orig, orig)
    row["canonical_sha"] = new
    row["answer_sha"] = new
    row["short_sha"] = short_sha(new)
    new_mal_files.append(row)

print(f"✅  Updated {len(mal_files)} rows")

# --------------------------------------------------------------------------- #
# 5️⃣  Update cases.csv (replace every SHA occurrence and sync range boundaries)
# --------------------------------------------------------------------------- #
cases = read_csv(DATASET_DIR / "cases.csv")

def replace_sha_field(value: str):
    """Replace any SHA(s) in *value* using the mapping."""
    if not value:
        return value
    if ";" in value:
        parts = value.split(";")
        return ";".join([sha_map.get(p.strip(), p.strip()) for p in parts])
    return sha_map.get(value.strip(), value.strip())

print("\n=== Updating cases.csv ===")
for row in cases:
    status = get_col(row, "status")
    cid = get_col(row, "case_id")
    repo_name = get_col(row, "repository")
    repo_path = repo_path_map.get(repo_name, None)

    for col in ("answer_labeled_shas", "canonical_malicious_shas"):
        if col in row:
            row[col] = replace_sha_field(row[col])

    if status == "ready" and cid in case_commit_map and repo_path:
        c_list = case_commit_map[cid]
        c_sorted = sorted(c_list, key=lambda x: int(get_col(x, "range_position") or "0"))
        
        first_sha = get_col(c_sorted[0], "sha")
        tip_sha   = get_col(c_sorted[-1], "sha")
        
        parent_out, rc = run_git(repo_path, ["rev-parse", f"{first_sha}^"])
        last_benign = parent_out if rc == 0 else ""
        
        row["range_first_sha"] = first_sha
        row["range_tip_sha"] = tip_sha
        row["last_benign_sha"] = last_benign
        row["range_revspec"] = f"{last_benign}..{tip_sha}"

print(f"✅  Updated {len(cases)} cases")

# --------------------------------------------------------------------------- #
# 6️⃣  Write everything to the fixed output folder
# --------------------------------------------------------------------------- #
print(f"\n📁  Writing corrected files to {FIXED_DIR}")
write_csv(FIXED_DIR / "commits.csv", commits[0].keys(), new_commits)
write_csv(FIXED_DIR / "malicious_files.csv", mal_files[0].keys(), new_mal_files)
write_csv(FIXED_DIR / "cases.csv", cases[0].keys(), cases)

# Copy static files unchanged
static_files = (
    "README.md", "cases.jsonl", "repositories.csv",
    "validation_report.json", "manifest.json",
    "Blackjack_Malicious_Commit_Dataset.xlsx",
    "Blackjack_Malicious_Commit_Dataset.zip",
)
for name in static_files:
    src = DATASET_DIR / name
    if src.exists():
        dst = FIXED_DIR / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())

print("🎉 Complete!")