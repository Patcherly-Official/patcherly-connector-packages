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
        added: List[str]
    ):
        self.orig_start = orig_start
        self.orig_len = orig_len
        self.new_start = new_start
        self.new_len = new_len
        self.context = context
        self.removed = removed
        self.added = added
    
    def can_apply_to(self, file_lines: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Check if this hunk can be applied to the file.
        
        Returns:
            Tuple of (can_apply: bool, error_message: Optional[str])
        """
        # Check bounds
        if self.orig_start < 1:
            return False, "Invalid start line (must be >= 1)"
        
        # Check if we have enough lines in file
        if self.orig_start - 1 + len(self.context) > len(file_lines):
            return False, f"Hunk starts at line {self.orig_start} but file has only {len(file_lines)} lines"
        
        # Check context matches
        start_idx = self.orig_start - 1
        for i, expected_line in enumerate(self.context):
            if start_idx + i >= len(file_lines):
                return False, f"Context mismatch: file too short"
            if file_lines[start_idx + i].rstrip('\r\n') != expected_line.rstrip('\r\n'):
                return False, f"Context mismatch at line {self.orig_start + i}"
        
        return True, None


class FilePatch:
    """Represents a patch for a single file."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.hunks: List[Hunk] = []
    
    def add_hunk(self, hunk: Hunk) -> None:
        """Add a hunk to this patch."""
        self.hunks.append(hunk)
    
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
            with open(file_path, 'r', encoding='utf-8') as f:
                file_lines = f.readlines()
        except Exception as e:
            return False, f"Cannot read file: {e}"
        
        # Check each hunk
        for i, hunk in enumerate(self.hunks):
            can_apply, error = hunk.can_apply_to(file_lines)
            if not can_apply:
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
                        hunk = self._parse_hunk(lines, i)
                        file_patch.add_hunk(hunk)
                        # Skip past hunk
                        while i < len(lines) and not lines[i].startswith('@@'):
                            i += 1
                        if i < len(lines) and lines[i].startswith('@@'):
                            continue  # Next hunk
                        break
                    
                    i += 1
                
                file_patches.append(file_patch)
            else:
                i += 1
        
        if not file_patches:
            raise PatchParseError("No file patches found in patch text")
        
        return file_patches
    
    def _parse_hunk(self, lines: List[str], start_idx: int) -> Hunk:
        """Parse a hunk from patch lines."""
        hunk_header = lines[start_idx]
        
        # Parse hunk header: @@ -orig_start,orig_len +new_start,new_len @@
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
        
        # Parse hunk content
        i = start_idx + 1
        while i < len(lines):
            line = lines[i]
            
            # End of hunk
            if line.startswith('@@') or line.startswith('---'):
                break
            
            if line.startswith(' '):
                # Context line (unchanged)
                context.append(line[1:])
            elif line.startswith('-'):
                # Removed line
                removed.append(line[1:])
            elif line.startswith('+'):
                # Added line
                added.append(line[1:])
            elif line.strip() == '':
                # Empty line in context
                context.append('')
            
            i += 1
        
        return Hunk(orig_start, orig_len, new_start, new_len, context, removed, added)
    
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
        
        # Remove old lines
        lines_to_remove = len(hunk.context) + len(hunk.removed)
        result = file_lines[:start_idx]
        
        # Add context + new lines
        for line in hunk.context:
            result.append(line if line.endswith('\n') else line + '\n')
        
        for line in hunk.added:
            result.append(line if line.endswith('\n') else line + '\n')
        
        # Add remaining lines
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

