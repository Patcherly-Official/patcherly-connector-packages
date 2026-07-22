"""
Patch Applicator for Python Agent
Handles parsing and applying unified diff patches to files.
"""

import ast
import logging
import os
import re
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class PatchParseError(Exception):
    """Error parsing patch format."""
    pass


class PatchApplyError(Exception):
    """Error applying patch."""
    pass


class FileLock:
    """File locking mechanism (cross-platform)."""
    
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.lock_file = Path(str(file_path) + '.lock')
        self.lock_fd = None
    
    def __enter__(self):
        """Acquire lock."""
        # Create lock file
        try:
            self.lock_fd = open(self.lock_file, 'x')
            self.lock_fd.write(str(os.getpid()))
            self.lock_fd.flush()
            return self
        except FileExistsError:
            raise PatchApplyError(f"File is locked: {self.file_path}")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Release lock."""
        if self.lock_fd:
            self.lock_fd.close()
        if self.lock_file.exists():
            self.lock_file.unlink()


class Hunk:
    """Represents a hunk (block of changes) in a patch."""
    
    def __init__(
        self,
        orig_start: int,
        orig_len: int,
        new_start: int,
        new_len: int,
        context: List[str],
        removed: List[str],
        added: List[str],
        segments: Optional[List[dict]] = None,
    ):
        self.orig_start = orig_start
        self.orig_len = orig_len
        self.new_start = new_start
        self.new_len = new_len
        self.context = context
        self.removed = removed
        self.added = added
        self.segments = segments or []

    def _orig_file_segments(self) -> List[dict]:
        if not self.segments:
            return []
        result = []
        past_added = False
        for seg in self.segments:
            seg_type = seg.get('type', '')
            if seg_type == 'added':
                past_added = True
                continue
            if past_added and seg_type == 'context':
                continue
            result.append(seg)
        return result

    def _orig_lines_in_hunk(self) -> int:
        if self.segments:
            return len(self._orig_file_segments())
        return len(self.context) + len(self.removed)
    
    def can_apply_to(self, file_lines: List[str]) -> Tuple[bool, Optional[str]]:
        if self.orig_start < 1:
            return False, "Invalid start line (must be >= 1)"
        
        orig_lines = self._orig_lines_in_hunk()
        if self.orig_start - 1 + orig_lines > len(file_lines):
            return False, f"Hunk starts at line {self.orig_start} but file has only {len(file_lines)} lines"
        
        if self.segments:
            idx = self.orig_start - 1
            for seg in self._orig_file_segments():
                if idx >= len(file_lines):
                    return False, "Context mismatch: file too short"
                expected = str(seg.get('text', '')).rstrip('\r\n')
                actual = file_lines[idx].rstrip('\r\n')
                if actual != expected:
                    return False, f"Context mismatch at line {idx + 1}"
                idx += 1
            return True, None
        
        start_idx = self.orig_start - 1
        for i, expected_line in enumerate(self.context):
            if start_idx + i >= len(file_lines):
                return False, "Context mismatch: file too short"
            if file_lines[start_idx + i].rstrip('\r\n') != expected_line.rstrip('\r\n'):
                return False, f"Context mismatch at line {self.orig_start + i}"
        
        return True, None

    def matches_post_image(self, file_lines: List[str]) -> Tuple[bool, Optional[str]]:
        if self.new_start < 1:
            return False, "Invalid new start line (must be >= 1)"

        idx = self.new_start - 1
        if self.segments:
            for seg in self.segments:
                seg_type = seg.get('type', '')
                if seg_type == 'removed':
                    continue
                if idx >= len(file_lines):
                    return False, "Post-image mismatch: file too short"
                expected = str(seg.get('text', '')).rstrip('\r\n')
                actual = file_lines[idx].rstrip('\r\n')
                if actual != expected:
                    return False, f"Post-image mismatch at line {idx + 1}"
                idx += 1
            return True, None

        for line in self.context:
            if idx >= len(file_lines):
                return False, "Post-image mismatch: file too short"
            if file_lines[idx].rstrip('\r\n') != line.rstrip('\r\n'):
                return False, f"Post-image mismatch at line {idx + 1}"
            idx += 1
        for line in self.added:
            if idx >= len(file_lines):
                return False, "Post-image mismatch: file too short"
            if file_lines[idx].rstrip('\r\n') != line.rstrip('\r\n'):
                return False, f"Post-image mismatch at line {idx + 1}"
            idx += 1

        return True, None

    def try_relocate_in_file(self, file_lines: List[str]) -> bool:
        can_apply, _ = self.can_apply_to(file_lines)
        if can_apply:
            return True
        if not self.segments or not self.removed:
            return False

        leading_context = []
        for seg in self.segments:
            seg_type = seg.get('type', '')
            if seg_type == 'removed':
                break
            if seg_type == 'context':
                leading_context.append(str(seg.get('text', '')).rstrip('\r\n'))

        removed_needle = self.removed[0].rstrip('\r\n')
        if not removed_needle:
            return False

        ctx_count = len(leading_context)
        header_delta = self.new_start - self.orig_start

        for i, line in enumerate(file_lines):
            if line.rstrip('\r\n') != removed_needle:
                continue
            ctx_start = i - ctx_count
            if ctx_start < 0:
                continue
            matched = True
            for j in range(ctx_count):
                if file_lines[ctx_start + j].rstrip('\r\n') != leading_context[j]:
                    matched = False
                    break
            if not matched:
                continue
            self.orig_start = ctx_start + 1
            self.new_start = self.orig_start + header_delta
            can_apply, _ = self.can_apply_to(file_lines)
            return can_apply

        return False


class FilePatch:
    """Represents a patch for a single file."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.hunks: List[Hunk] = []
    
    def add_hunk(self, hunk: Hunk) -> None:
        """Add a hunk to this patch."""
        self.hunks.append(hunk)
    
    def _read_file_lines(self, file_path: Path) -> List[str]:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        lines = content.split('\n')
        result = []
        for idx, line in enumerate(lines):
            if idx < len(lines) - 1 or content.endswith('\n'):
                result.append(line + '\n')
            else:
                result.append(line)
        return result

    def can_apply_to(self, file_path: Path) -> Tuple[bool, Optional[str]]:
        """
        Check if this patch can be applied to the file.
        
        Returns:
            Tuple of (can_apply: bool, error_message: Optional[str])
        """
        if not file_path.exists():
            # If file doesn't exist, check if all hunks are additions
            for hunk in self.hunks:
                if hunk.orig_len > 0:
                    return False, f"File does not exist and patch contains deletions"
            return True, None
        
        try:
            file_lines = self._read_file_lines(file_path)
        except Exception as e:
            return False, f"Cannot read file: {e}"
        
        for i, hunk in enumerate(self.hunks):
            can_apply, _ = hunk.can_apply_to(file_lines)
            if not can_apply:
                hunk.try_relocate_in_file(file_lines)
            can_apply, error = hunk.can_apply_to(file_lines)
            if not can_apply:
                return False, f"Hunk {i+1}: {error}"
        
        return True, None

    def matches_post_image(self, file_path: Path) -> Tuple[bool, Optional[str]]:
        if not file_path.exists():
            return False, "File does not exist"

        try:
            file_lines = self._read_file_lines(file_path)
        except Exception as e:
            return False, f"Cannot read file: {e}"

        for i, hunk in enumerate(self.hunks):
            matches, error = hunk.matches_post_image(file_lines)
            if not matches:
                return False, f"Hunk {i+1}: {error}"

        return True, None


class PatchApplicator:
    """Parses and applies unified diff patches."""
    
    def __init__(self):
        """Initialize the patch applicator."""
        logger.info("Initialized PatchApplicator")
    
    def parse_patch(self, patch_text: str) -> List[FilePatch]:
        """
        Parse unified diff format into FilePatch objects.
        
        Args:
            patch_text: Unified diff format patch string
        
        Returns:
            List of FilePatch objects
        
        Raises:
            PatchParseError: If patch cannot be parsed
        """
        file_patches = []
        lines = patch_text.split('\n')
        
        i = 0
        while i < len(lines):
            # Look for file header: --- a/path
            if lines[i].startswith('---'):
                file_path_match = re.match(r'---\s+a/(.+)', lines[i])
                if not file_path_match:
                    # Try without 'a/' prefix
                    file_path_match = re.match(r'---\s+(.+)', lines[i])
                    if not file_path_match:
                        i += 1
                        continue
                
                file_path = file_path_match.group(1).strip()
                
                # Skip to +++ line
                i += 1
                if i >= len(lines) or not lines[i].startswith('+++'):
                    raise PatchParseError(f"Missing +++ line after --- for {file_path}")
                
                # Create FilePatch
                file_patch = FilePatch(file_path)
                
                # Parse hunks
                i += 1
                while i < len(lines):
                    line = lines[i]
                    
                    # Empty line between hunks
                    if not line.strip():
                        i += 1
                        continue
                    
                    # New file header - done with this file
                    if line.startswith('---'):
                        break
                    
                    # Hunk header: @@ -orig_start,orig_len +new_start,new_len @@
                    if line.startswith('@@'):
                        hunk, i = self._parse_hunk(lines, i)
                        file_patch.add_hunk(hunk)
                        continue
                    
                    i += 1
                
                file_patches.append(file_patch)
            else:
                i += 1
        
        if not file_patches:
            raise PatchParseError("No file patches found in patch text")
        
        return file_patches
    
    def _parse_hunk(self, lines: List[str], start_idx: int) -> Tuple[Hunk, int]:
        """Parse a hunk from patch lines; returns (Hunk, next_line_index)."""
        hunk_header = lines[start_idx]
        
        # Parse hunk header: @@ -orig_start,orig_len +new_start,new_len @@ [optional section]
        # Optional trailing text after the second @@ is valid unified-diff (git style).
        match = re.match(r'@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@', hunk_header)
        if not match:
            raise PatchParseError(f"Invalid hunk header: {hunk_header}")
        
        orig_start = int(match.group(1))
        orig_len = int(match.group(2) or 1)
        new_start = int(match.group(3))
        new_len = int(match.group(4) or 1)
        
        context = []
        removed = []
        added = []
        segments = []
        
        # Parse hunk content
        i = start_idx + 1
        while i < len(lines):
            line = lines[i]
            
            # End of hunk
            if line.startswith('@@') or line.startswith('---'):
                break
            
            if line.startswith(' '):
                text = line[1:]
                context.append(text)
                segments.append({'type': 'context', 'text': text})
            elif line.startswith('-'):
                text = line[1:]
                removed.append(text)
                segments.append({'type': 'removed', 'text': text})
            elif line.startswith('+'):
                text = line[1:]
                added.append(text)
                segments.append({'type': 'added', 'text': text})
            elif line.strip() == '':
                context.append('')
                segments.append({'type': 'context', 'text': ''})
            
            i += 1
        
        return Hunk(orig_start, orig_len, new_start, new_len, context, removed, added, segments), i
    
    def apply_patch(
        self,
        file_patch: FilePatch,
        file_path: Path,
        dry_run: bool = False,
        verify_syntax: bool = True
    ) -> Tuple[bool, str, Optional[List[str]]]:
        """
        Apply a patch to a file.
        
        Args:
            file_patch: FilePatch to apply
            file_path: Path to file to patch
            dry_run: If True, simulate without modifying file
            verify_syntax: If True, validate syntax after application
        
        Returns:
            Tuple of (success: bool, message: str, syntax_errors: Optional[List[str]])
        """
        # Check if patch can be applied
        can_apply, error = file_patch.can_apply_to(file_path)
        if not can_apply:
            already, _ = file_patch.matches_post_image(file_path)
            if already:
                return True, f"Patch already applied to {file_path}", None
            return False, f"Cannot apply patch: {error}", None
        
        if dry_run:
            return True, f"Dry-run: Patch would be applied successfully to {file_path}", None
        
        # Acquire file lock
        try:
            with FileLock(file_path):
                # Read original file
                if file_path.exists():
                    with open(file_path, 'r', encoding='utf-8') as f:
                        original_lines = f.readlines()
                else:
                    original_lines = []
                
                # Apply hunks (in reverse order to maintain line numbers)
                modified_lines = original_lines.copy()
                
                # Sort hunks by start line in reverse order
                sorted_hunks = sorted(file_patch.hunks, key=lambda h: h.orig_start, reverse=True)
                
                for hunk in sorted_hunks:
                    modified_lines = self._apply_hunk(hunk, modified_lines)
                
                # Write modified file
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    f.writelines(modified_lines)
                
                # Verify syntax if requested
                syntax_errors = None
                if verify_syntax:
                    syntax_ok, errors = self._verify_syntax(file_path)
                    if not syntax_ok:
                        # Restore original file
                        with open(file_path, 'w', encoding='utf-8', newline='') as f:
                            f.writelines(original_lines)
                        return False, f"Syntax validation failed", errors
                    syntax_errors = errors if errors else []
                
                return True, f"Patch applied successfully to {file_path}", syntax_errors
                
        except PatchApplyError as e:
            return False, str(e), None
        except Exception as e:
            logger.error(f"Error applying patch: {e}", exc_info=True)
            return False, f"Error applying patch: {e}", None
    
    def _apply_hunk(self, hunk: Hunk, file_lines: List[str]) -> List[str]:
        """Apply a single hunk to file lines."""
        start_idx = hunk.orig_start - 1

        if hunk.segments:
            result = file_lines[:start_idx]
            orig_consumed = 0
            past_added = False
            trailing_decorative = []
            for seg in hunk.segments:
                text = str(seg.get('text', ''))
                seg_type = seg.get('type', '')
                if seg_type == 'context':
                    if past_added:
                        trailing_decorative.append(text)
                        continue
                    result.append(text if text.endswith('\n') else text + '\n')
                    orig_consumed += 1
                elif seg_type == 'removed':
                    orig_consumed += 1
                elif seg_type == 'added':
                    past_added = True
                    result.append(text if text.endswith('\n') else text + '\n')
            remaining_start = start_idx + orig_consumed
            if remaining_start < len(file_lines):
                result.extend(file_lines[remaining_start:])
            elif trailing_decorative:
                for text in trailing_decorative:
                    result.append(text if text.endswith('\n') else text + '\n')
            return result
        
        lines_to_remove = len(hunk.context) + len(hunk.removed)
        result = file_lines[:start_idx]
        
        for line in hunk.context:
            result.append(line if line.endswith('\n') else line + '\n')
        
        for line in hunk.added:
            result.append(line if line.endswith('\n') else line + '\n')
        
        remaining_start = start_idx + lines_to_remove
        if remaining_start < len(file_lines):
            result.extend(file_lines[remaining_start:])
        
        return result
    
    def _verify_syntax(self, file_path: Path) -> Tuple[bool, List[str]]:
        """
        Verify syntax of a Python file.
        
        Returns:
            Tuple of (is_valid: bool, errors: List[str])
        """
        if not file_path.suffix == '.py':
            # For non-Python files, assume valid
            return True, []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            try:
                ast.parse(source, filename=str(file_path))
                return True, []
            except SyntaxError as e:
                return False, [f"Syntax error at line {e.lineno}: {e.msg}"]
            except Exception as e:
                return False, [f"Parse error: {e}"]
        except Exception as e:
            return False, [f"Cannot read file for syntax check: {e}"]

