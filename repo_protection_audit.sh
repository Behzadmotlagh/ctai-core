#!/usr/bin/env bash
set -euo pipefail

# USAGE:
#   GH_PAT=ghp_xxx ./repo_protection_audit.sh
# or
#   ensure `gh` is installed and logged in, then ./repo_protection_audit.sh

OUT_DIR="repo_audit_output"
mkdir -p "$OUT_DIR"

REPO_FULL="$(git remote get-url origin 2>/dev/null || true)"
if [[ -z "$REPO_FULL" ]]; then
  echo "ERROR: no origin remote configured. set origin to git@github.com:USER/REPO.git or https://github.com/USER/REPO.git" | tee "$OUT_DIR/error.txt"
  exit 1
fi

# normalize owner/repo
if [[ "$REPO_FULL" =~ github.com[:/]+(.+/.+)(\.git)?$ ]]; then
  OWNER_REPO="${BASH_REMATCH[1]}"
else
  echo "ERROR: unable to parse origin url: $REPO_FULL" | tee "$OUT_DIR/error.txt"
  exit 1
fi

echo "Audit start: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" | tee "$OUT_DIR/audit_run.txt"
echo "Repository: $OWNER_REPO" | tee -a "$OUT_DIR/audit_run.txt"

# helper: call GitHub API using gh if available, otherwise curl+GH_PAT
call_api() {
  local method="$1"; shift
  local path="$1"; shift
  if command -v gh >/dev/null 2>&1; then
    gh api -X "$method" "/repos/$OWNER_REPO$path" "$@"
  else
    if [[ -z "${GH_PAT:-}" ]]; then
      echo "ERROR: gh not available and GH_PAT not set" >&2
      return 2
    fi
    curl -sS -H "Authorization: token $GH_PAT" -H "Accept: application/vnd.github.v3+json" -X "$method" "https://api.github.com/repos/$OWNER_REPO$path" "$@"
  fi
}

# 1) local git overview
git fetch --all --prune 2>/dev/null || true
git branch -avv > "$OUT_DIR/branches.txt"
git tag -l > "$OUT_DIR/tags.txt"
du -sh .git 2>/dev/null | tee "$OUT_DIR/git_dir_size.txt"
du -sh . 2>/dev/null | tee "$OUT_DIR/working_tree_size.txt"
git --no-pager log --pretty=format:'%h %ad %an %s' --date=iso --max-count=200 > "$OUT_DIR/recent_commits.txt"
git --no-pager log --name-only --pretty=format:'%h %ad %an %s' --date=iso --max-count=200 > "$OUT_DIR/recent_commits_with_files.txt"

# 2) largest blobs in history
git rev-list --objects --all \
  | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' \
  | awk '$1=="blob" {print $3, $2, $4}' \
  | sort -n -k1 \
  | tail -n 50 \
  > "$OUT_DIR/largest_blobs.txt"

# 3) current workspace large files
find . -type f -not -path "./.git/*" -printf "%s\t%p\n" \
  | sort -nr \
  | head -n 100 \
  > "$OUT_DIR/top_fs_files.txt"

# 4) quick secrets scan (heuristic)
GREP_PATTERNS="PRIVATE[-_ ]KEY|BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|API[_-]?KEY|SECRET[_-]?|TOKEN[_-]?|PASSWORD|passwd|-----BEGIN CERTIFICATE-----"
git grep -n --break --heading -E "$GREP_PATTERNS" $(git rev-list --all) 2>/dev/null || true > "$OUT_DIR/secrets_in_history.txt" || true
grep -RIn --exclude-dir=.git -E "$GREP_PATTERNS" . 2>/dev/null | head -n 500 > "$OUT_DIR/secrets_in_worktree.txt" || true

# 5) check CODEOWNERS
if [[ -f .github/CODEOWNERS || -f CODEOWNERS ]]; then
  echo "CODEOWNERS found" > "$OUT_DIR/codeowners.txt"
  { [[ -f .github/CODEOWNERS ]] && sed -n '1,200p' .github/CODEOWNERS; [[ -f CODEOWNERS ]] && sed -n '1,200p' CODEOWNERS; } > "$OUT_DIR/codeowners.txt"
else
  echo "NO CODEOWNERS" > "$OUT_DIR/codeowners.txt"
fi

# 6) GitHub: Branch Protection for main
echo "Fetching branch protection for 'main'..." | tee -a "$OUT_DIR/audit_run.txt"
PROT_JSON="$(call_api GET /branches/main/protection 2>/dev/null || true)"
if [[ -z "$PROT_JSON" ]]; then
  echo "No branch protection rule found for main or insufficient permissions" > "$OUT_DIR/branch_protection.txt"
else
  echo "$PROT_JSON" > "$OUT_DIR/branch_protection.json"
  # extract useful bits
  echo "required_status_checks:" > "$OUT_DIR/branch_protection.txt"
  if command -v jq >/dev/null 2>&1; then
    jq '.required_status_checks' "$OUT_DIR/branch_protection.json" >> "$OUT_DIR/branch_protection.txt"
  else
    grep -E '"required_status_checks"|"strict"|"contexts"' -n "$OUT_DIR/branch_protection.json" >> "$OUT_DIR/branch_protection.txt" || true
  fi
fi

# 7) GitHub: list workflows and latest runs
echo "Fetching workflows list..." | tee -a "$OUT_DIR/audit_run.txt"
WORKFLOWS_JSON="$(call_api GET /actions/workflows 2>/dev/null || true)"
echo "$WORKFLOWS_JSON" > "$OUT_DIR/workflows_list.json"
if command -v jq >/dev/null 2>&1; then
  jq -r '.workflows[] | "\(.id) \(.name) \(.path) \(.state)"' "$OUT_DIR/workflows_list.json" > "$OUT_DIR/workflows_summary.txt" || true
else
  grep -n '"name"' "$OUT_DIR/workflows_list.json" | sed -n '1,200p' > "$OUT_DIR/workflows_summary.txt" || true
fi

# for each workflow, get last 3 runs
echo "" > "$OUT_DIR/workflows_runs.txt"
if command -v jq >/dev/null 2>&1; then
  for id in $(jq -r '.workflows[].id' "$OUT_DIR/workflows_list.json"); do
    echo "Workflow ID: $id" >> "$OUT_DIR/workflows_runs.txt"
    call_api GET /actions/workflows/"$id"/runs\?per_page\=3 2>/dev/null | jq '.workflow_runs[] | {id:.id, head_branch:.head_branch, head_sha:.head_sha, status:.status, conclusion:.conclusion, event:.event, created_at:.created_at}' >> "$OUT_DIR/workflows_runs.txt" || true
    echo "----" >> "$OUT_DIR/workflows_runs.txt"
  done
else
  # fallback: call runs for each workflow id by parsing raw
  ids=$(grep -o '"id":[0-9]*' "$OUT_DIR/workflows_list.json" | sed 's/"id"://g' | uniq)
  for id in $ids; do
    echo "Workflow ID: $id" >> "$OUT_DIR/workflows_runs.txt"
    call_api GET /actions/workflows/"$id"/runs\?per_page\=3 2>/dev/null >> "$OUT_DIR/workflows_runs.txt" || true
    echo "----" >> "$OUT_DIR/workflows_runs.txt"
  done
fi

# 8) Latest run job details for PRs or main pushes (look for most recent run)
echo "Fetching recent workflow runs (global)..." | tee -a "$OUT_DIR/audit_run.txt"
call_api GET /actions/runs\?per_page\=10 2>/dev/null > "$OUT_DIR/recent_workflow_runs.json" || true
if command -v jq >/dev/null 2>&1; then
  jq -r '.workflow_runs[] | {id:.id, name:.name, head_branch:.head_branch, status:.status, conclusion:.conclusion, event:.event, created_at:.created_at}' "$OUT_DIR/recent_workflow_runs.json" > "$OUT_DIR/recent_workflow_runs_summary.txt"
else
  head -n 200 "$OUT_DIR/recent_workflow_runs.json" > "$OUT_DIR/recent_workflow_runs_summary.txt"
fi

# 9) summary report
{
  echo "Repository: $OWNER_REPO"
  echo "Audit time: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo
  echo "Branches:"
  cat "$OUT_DIR/branches.txt" | sed -n '1,200p'
  echo
  echo "Top 10 largest blobs in history (size,object,path):"
  head -n 10 "$OUT_DIR/largest_blobs.txt"
  echo
  echo "Top 10 large files in workspace (size, path):"
  head -n 10 "$OUT_DIR/top_fs_files.txt"
  echo
  echo "Recent workflow runs summary:"
  head -n 30 "$OUT_DIR/recent_workflow_runs_summary.txt"
  echo
  echo "Branch protection (main):"
  if [[ -f "$OUT_DIR/branch_protection.json" ]]; then
    if command -v jq >/dev/null 2>&1; then
      jq '.required_status_checks' "$OUT_DIR/branch_protection.json"
    else
      cat "$OUT_DIR/branch_protection.txt"
    fi
  else
    cat "$OUT_DIR/branch_protection.txt"
  fi
  echo
  echo "CODEOWNERS:"
  cat "$OUT_DIR/codeowners.txt"
  echo
  echo "Secrets heuristics (history, worktree):"
  echo "history matches:"
  head -n 30 "$OUT_DIR/secrets_in_history.txt"
  echo "worktree matches:"
  head -n 30 "$OUT_DIR/secrets_in_worktree.txt"
} > "$OUT_DIR/report_summary.txt"

echo "Audit complete. Summary: $OUT_DIR/report_summary.txt"
echo "Detailed outputs: $OUT_DIR/"
