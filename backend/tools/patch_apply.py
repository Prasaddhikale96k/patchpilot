"""SEARCH/REPLACE patch parser + applier (prompt 03, secure-patch-writer skill).

Format produced by the coder LLM:

    FILE: app/routes.py
    <<<<<<< SEARCH
    <exact current text>
    =======
    <replacement text>
    >>>>>>> REPLACE

An empty SEARCH section means "create new file". Multiple blocks per file
are allowed and applied in order.
"""

from __future__ import annotations

import difflib
import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_BLOCK_RE = re.compile(
    r"^FILE:\s*(?P<file>.+?)\s*$\n"
    r"^<<<<<<<\s*SEARCH\s*$\n"
    r"(?P<search>.*?)"
    r"^=======\s*$\n"
    r"(?P<replace>.*?)"
    r"^>>>>>>>\s*REPLACE\s*$\n?",
    re.MULTILINE | re.DOTALL,
)


class PatchApplyError(RuntimeError):
    """A SEARCH block could not be applied (message goes back to the coder)."""


@dataclass
class PatchBlock:
    file: str
    search: str
    replace: str


@dataclass
class AppliedPatch:
    files_changed: list[str] = field(default_factory=list)
    diff: str = ""
    lines_added: int = 0
    lines_removed: int = 0


def parse_blocks(text: str) -> list[PatchBlock]:
    """Parse every FILE:/SEARCH/REPLACE block; raises on empty result."""
    blocks = [PatchBlock(file=m.group("file").strip(),
                         search=m.group("search"),
                         replace=m.group("replace"))
              for m in _BLOCK_RE.finditer(text or "")]
    if not blocks:
        raise PatchApplyError("No FILE:/SEARCH/REPLACE blocks found in patch.")
    return blocks


def _resolve(repo_root: str, rel_file: str) -> str:
    """Resolve a block path inside the repo; reject escapes."""
    root = os.path.realpath(repo_root)
    target = os.path.realpath(os.path.join(root, rel_file))
    if target != root and not target.startswith(root + os.sep):
        raise PatchApplyError(f"Refusing to write outside the repo: {rel_file}")
    return target


def _closest_lines(current: list[str], search: list[str], width: int = 4) -> str:
    """Best-guess location for a missing block, for the error message."""
    if not search or not current:
        return "file is empty" if not current else "no search lines"
    first = search[0].strip()
    hits = [i for i, line in enumerate(current) if line.strip() == first]
    if not hits:
        # Fall back to the most overlapping window by token overlap.
        want = set(first.split())
        best, best_n = 0, -1
        for i in range(len(current)):
            overlap = len(want & set(current[i].split()))
            if overlap > best_n:
                best, best_n = i, overlap
        hits = [best]
    start = max(0, hits[0] - 1)
    shown = current[start:start + width]
    numbered = "; ".join(f"{start + 1 + i}: {line.strip()[:80]}"
                         for i, line in enumerate(shown))
    return f"lines {start + 1}-{start + len(shown)}: {numbered}"


def _norm_lines(text: str) -> list[str]:
    # Comparison only: the replacement keeps the model's own indentation,
    # so stripping both ends here cannot mis-indent the result.
    return [line.replace("\t", "    ").strip() for line in text.splitlines()]


def _apply_one(current: str, block: PatchBlock, index: int) -> str:
    """Apply one block: exact match (exactly once), else whitespace-tolerant."""
    if not block.search.strip():
        return block.replace  # new file (empty SEARCH creates the file)
    occurrences = current.count(block.search)
    if occurrences == 1:
        return current.replace(block.search, block.replace, 1)
    if occurrences > 1:
        raise PatchApplyError(
            f"SEARCH block {index} for {block.file} matches {occurrences} "
            f"times — it must match exactly once.")
    # Whitespace-tolerant line match.
    current_lines = current.splitlines()
    search_lines = block.search.splitlines()
    norm_current = _norm_lines(current)
    norm_search = _norm_lines(block.search)
    width = len(search_lines)
    candidates = [
        i for i in range(len(current_lines) - width + 1)
        if norm_current[i:i + width] == norm_search
    ]
    if len(candidates) == 1:
        start = candidates[0]
        new_lines = (current_lines[:start]
                     + block.replace.splitlines()
                     + current_lines[start + width:])
        result = "\n".join(new_lines)
        if current.endswith("\n"):
            result += "\n"
        return result
    if len(candidates) > 1:
        raise PatchApplyError(
            f"SEARCH block {index} for {block.file} matches {len(candidates)} "
            f"times — it must match exactly once.")
    raise PatchApplyError(
        f"SEARCH block {index} for {block.file} not found. "
        f"Closest lines: {_closest_lines(current_lines, search_lines)}")


def apply_blocks(repo_root: str, blocks: list[PatchBlock]) -> AppliedPatch:
    """Apply blocks in order; returns files_changed + unified diff + counts."""
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    for index, block in enumerate(blocks, start=1):
        target = _resolve(repo_root, block.file)
        if target not in after:
            if os.path.isfile(target):
                with open(target, "r", encoding="utf-8",
                          errors="replace") as handle:
                    after[target] = handle.read()
            else:
                after[target] = ""
            before[target] = after[target]
        after[target] = _apply_one(after[target], block, index)

    result = AppliedPatch()
    diff_lines: list[str] = []
    for target, new_text in after.items():
        old_text = before[target]
        if new_text == old_text:
            continue
        rel = os.path.relpath(target, os.path.realpath(repo_root))
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="") as handle:
            handle.write(new_text)
        result.files_changed.append(rel.replace("\\", "/"))
        diff_lines.extend(difflib.unified_diff(
            old_text.splitlines(), new_text.splitlines(),
            fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm=""))
    result.diff = "\n".join(diff_lines)
    result.lines_added = sum(1 for l in diff_lines
                             if l.startswith("+") and not l.startswith("+++"))
    result.lines_removed = sum(1 for l in diff_lines
                               if l.startswith("-") and not l.startswith("---"))
    logger.info("patch_apply: %d file(s) changed (+%d −%d)",
                len(result.files_changed), result.lines_added,
                result.lines_removed)
    return result
