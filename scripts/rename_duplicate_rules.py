#!/usr/bin/env python3
"""
Rename duplicate rule IDs in opengrep-rules repository.
Scheme: <lang>-<framework>-<original-id>
Only rules with duplicate IDs are renamed. Unique IDs are left as-is.
"""
import os
import re
import sys
from collections import defaultdict

# Path segments to strip from qualifier (noise words)
NOISE_WORDS = {'security', 'audit', 'injection', 'xss', 'src', 'lib'}

# IDs that are test/template artifacts, not real rules
SKIP_IDS = {
    '$ID', '$OUTER_RULEID', '$RULEID', '$X', '...',
    'bad-1', 'bad-2', 'bad-first', 'bad-second',
    'example-1', 'example-2', 'other-rule', 'half-written-crypto-example',
    'check-added-large-files', 'check-case-conflict', 'check-executables-have-shebangs',
    'check-merge-conflict', 'check-symlinks', 'check-yaml',
    'subprocess-run', 'subprocess-run-2',
}

# Files to skip (not rule files)
SKIP_FILE_PATTERNS = ['.test.yaml', '.test.yml', '.github/', '.pre-commit']


def is_rule_file(relpath):
    if not (relpath.endswith('.yaml') or relpath.endswith('.yml')):
        return False
    return not any(p in relpath for p in SKIP_FILE_PATTERNS)


def extract_rule_ids(root_dir):
    """Extract rule_id -> list of relative file paths."""
    rules = defaultdict(list)
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            fpath = os.path.join(dirpath, f)
            relpath = os.path.relpath(fpath, root_dir)
            if not is_rule_file(relpath):
                continue
            try:
                with open(fpath) as fh:
                    for line in fh:
                        m = re.match(r'^\s*-?\s*id:\s*(.+)', line)
                        if m:
                            rid = m.group(1).strip().strip('"').strip("'")
                            if rid not in SKIP_IDS:
                                rules[rid].append(relpath)
            except Exception:
                pass
    return dict(rules)


def make_qualifier(relpath):
    """Extract meaningful qualifier from file path."""
    parts = relpath.split(os.sep)
    parts = parts[:-1]  # remove filename

    if parts and parts[0] == 'problem-based-packs':
        parts = parts[1:]

    meaningful = [p for p in parts if p not in NOISE_WORDS]
    return '-'.join(meaningful) if meaningful else 'root'


def compute_renames(rules):
    """For each duplicate ID, compute new unique IDs. Returns dict: (old_id, relpath) -> new_id."""
    renames = {}

    for old_id, files in sorted(rules.items()):
        real_files = sorted(set(f for f in files if is_rule_file(f)))
        if len(real_files) <= 1:
            continue

        # Try qualifier-based naming
        qualifiers = [(f, make_qualifier(f)) for f in real_files]
        quals = [q for _, q in qualifiers]

        if len(set(quals)) == len(quals):
            # Qualifiers are unique
            for f, q in qualifiers:
                renames[(old_id, f)] = f"{q}-{old_id}"
        else:
            # Need more path depth — use ALL path segments (no noise filtering)
            for f in real_files:
                parts = f.split(os.sep)
                fname_stem = parts[-1].rsplit('.', 1)[0]
                all_parts = parts[:-1] + [fname_stem]
                full_q = '-'.join(all_parts)
                renames[(old_id, f)] = full_q

    # Verify no collisions
    new_ids = list(renames.values())
    if len(set(new_ids)) != len(new_ids):
        # Find collisions
        from collections import Counter
        dupes = [nid for nid, cnt in Counter(new_ids).items() if cnt > 1]
        print(f"ERROR: {len(dupes)} collisions in new IDs!", file=sys.stderr)
        for d in dupes:
            entries = [(k, v) for k, v in renames.items() if v == d]
            print(f"  {d}:", file=sys.stderr)
            for (old_id, f), new_id in entries:
                print(f"    {old_id} <- {f}", file=sys.stderr)
        sys.exit(1)

    return renames


def apply_renames(root_dir, renames, dry_run=False):
    """Apply renames to YAML files. Only changes `id:` field values."""
    # Group renames by file
    file_renames = defaultdict(dict)  # relpath -> {old_id: new_id}
    for (old_id, relpath), new_id in renames.items():
        file_renames[relpath][old_id] = new_id

    changed_count = 0
    for relpath, id_map in sorted(file_renames.items()):
        fpath = os.path.join(root_dir, relpath)
        try:
            with open(fpath) as f:
                lines = f.readlines()
        except Exception as e:
            print(f"  SKIP {relpath}: {e}", file=sys.stderr)
            continue

        new_lines = []
        changed = False
        for line in lines:
            m = re.match(r'^(\s*-?\s*id:\s*)(.+)(\s*)$', line)
            if m:
                prefix, current_id, suffix = m.group(1), m.group(2).strip().strip('"').strip("'"), m.group(3)
                if current_id in id_map:
                    new_id = id_map[current_id]
                    new_line = f"{prefix}{new_id}{suffix}"
                    if not dry_run:
                        new_lines.append(new_line)
                    else:
                        new_lines.append(line)
                    print(f"  {relpath}: {current_id} -> {new_id}")
                    changed = True
                    changed_count += 1
                    continue
            new_lines.append(line)

        if changed and not dry_run:
            with open(fpath, 'w') as f:
                f.writelines(new_lines)

    return changed_count


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <rules-dir> [--dry-run]", file=sys.stderr)
        sys.exit(1)

    root_dir = sys.argv[1]
    dry_run = '--dry-run' in sys.argv

    print(f"Scanning {root_dir}...")
    rules = extract_rule_ids(root_dir)

    duplicates = {k: v for k, v in rules.items() if len(set(v)) > 1}
    print(f"Found {len(rules)} unique rule IDs, {len(duplicates)} with duplicates")

    if not duplicates:
        print("No duplicates found!")
        return

    renames = compute_renames(rules)
    print(f"Computed {len(renames)} renames, 0 collisions")

    if dry_run:
        print("\n--- DRY RUN ---")

    changed = apply_renames(root_dir, renames, dry_run=dry_run)
    print(f"\n{'Would change' if dry_run else 'Changed'} {changed} rule IDs in YAML files")

    # Verify: re-scan and check for remaining duplicates
    if not dry_run:
        print("\nVerifying...")
        rules_after = extract_rule_ids(root_dir)
        dups_after = {k: v for k, v in rules_after.items() if len(set(v)) > 1}
        if dups_after:
            print(f"WARNING: {len(dups_after)} duplicates remain!")
            for rid, files in sorted(dups_after.items()):
                print(f"  {rid}: {sorted(set(files))}")
        else:
            print("OK: 0 duplicates remaining")


if __name__ == '__main__':
    main()
