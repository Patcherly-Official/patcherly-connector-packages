<?php
/**
 * Parse and apply unified-diff patches with WordPress-aware path containment and locking.
 */

if (!defined('ABSPATH')) { exit; }

require_once __DIR__ . '/storage_paths.php';

class Patcherly_PatchParseError extends Exception {
}

class Patcherly_PatchApplyError extends Exception {
}

class Patcherly_FileLock {
    /**
     * Advisory file lock using a sha1-keyed sidecar in wp-content/uploads/patcherly/locks/.
     * Never written next to the target — that would collide with WP auto-updates and expose
     * a public artifact under wp-content/plugins/. Low-level fopen/flock are kept because
     * WP_Filesystem has no O_EXCL or flock equivalent; the lockfile itself never holds tainted data.
     */
    private $filePath;
    private $lockFile;
    private $lockHandle = null;

    public function __construct($filePath) {
        $this->filePath = $filePath;
        $this->lockFile = self::lock_path_for($filePath);
    }

    /** Compute the lockfile path for a target. Public so tests can assert the policy. */
    public static function lock_path_for(string $filePath): string {
        $dir = function_exists('patcherly_locks_dir')
            ? patcherly_locks_dir()
            : trailingslashit(sys_get_temp_dir()) . 'patcherly_locks';
        self::ensure_lock_dir_protection($dir);
        return $dir . '/' . sha1($filePath) . '.lock';
    }

    /** Idempotently create the locks dir and install .htaccess + web.config + index.php deny rules. */
    private static function ensure_lock_dir_protection(string $dir): void {
        if (function_exists('patcherly_ensure_directory_protection')) {
            patcherly_ensure_directory_protection($dir);
            return;
        }
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        if (!is_dir($dir)) {
            return;
        }
        $files = [
            $dir . '/.htaccess'  => "Order Allow,Deny\nDeny from all\n",
            $dir . '/web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <system.webServer>\n    <authorization>\n      <deny users=\"*\" />\n    </authorization>\n  </system.webServer>\n</configuration>\n",
            $dir . '/index.php'  => "<?php\n// Silence is golden.\n",
        ];
        foreach ($files as $path => $contents) {
            if (file_exists($path) && filesize($path) > 0) {
                continue;
            }
            try {
                if (function_exists('WP_Filesystem')) {
                    require_once ABSPATH . 'wp-admin/includes/file.php';
                    if (WP_Filesystem()) {
                        global $wp_filesystem;
                        if ($wp_filesystem && $wp_filesystem->put_contents($path, $contents, defined('FS_CHMOD_FILE') ? FS_CHMOD_FILE : 0644)) {
                            continue;
                        }
                    }
                }
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- WP_Filesystem fallback for early-boot / CLI paths.
                @file_put_contents($path, $contents);
            } catch (\Throwable $e) {
                if (function_exists('patcherly_debug_log')) {
                    patcherly_debug_log(__METHOD__ . ': ' . $e->getMessage());
                }
            }
        }
    }

    public function acquire() {
        try {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- advisory file lock (O_EXCL via 'x'); WP_Filesystem has no equivalent.
            $this->lockHandle = fopen($this->lockFile, 'x');
            if ($this->lockHandle === false) {
                throw new Patcherly_PatchApplyError(esc_html("File is locked: {$this->filePath}"));
            }
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- writing PID into our own lockfile; not user-visible content.
            fwrite($this->lockHandle, getmypid() . "\n");
            fflush($this->lockHandle);
            return $this;
        } catch (Exception $e) {
            if (file_exists($this->lockFile)) {
                throw new Patcherly_PatchApplyError(esc_html("File is locked: {$this->filePath}"));
            }
            throw $e;
        }
    }

    public function release() {
        if ($this->lockHandle) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- paired with the 'x'-mode fopen above.
            fclose($this->lockHandle);
            $this->lockHandle = null;
        }
        if (file_exists($this->lockFile)) {
            wp_delete_file($this->lockFile);
        }
    }
}

/** One hunk (block of changes) inside a unified diff. */
class Patcherly_Hunk {
    public $origStart;
    public $origLen;
    public $newStart;
    public $newLen;
    public $context;
    public $removed;
    public $added;
    /** @var list<array{type:string,text:string}> Diff-body order (context/removed/added). */
    public $segments;

    /**
     * @param list<array{type:string,text:string}> $segments
     */
    public function __construct($origStart, $origLen, $newStart, $newLen, $context, $removed, $added, $segments = []) {
        $this->origStart = $origStart;
        $this->origLen = $origLen;
        $this->newStart = $newStart;
        $this->newLen = $newLen;
        $this->context = $context;
        $this->removed = $removed;
        $this->added = $added;
        $this->segments = $segments;
    }

    /**
     * @return int Index of last added/removed segment, or -1.
     */
    private function last_change_segment_index(): int {
        $last = -1;
        foreach ($this->segments as $i => $seg) {
            $type = $seg['type'] ?? '';
            if ($type === 'added' || $type === 'removed') {
                $last = (int) $i;
            }
        }
        return $last;
    }

    /**
     * Segments that consume lines from the original file.
     * Trailing context after the last change is decorative in many AI diffs and must not
     * be validated against (or consume) lines past a truncated/corrupt target file.
     * Mid-hunk context between multiple change sites must still be matched.
     *
     * @return list<array{type:string,text:string}>
     */
    private function orig_file_segments(): array {
        if ($this->segments === []) {
            return [];
        }
        $lastChange = $this->last_change_segment_index();
        $result = [];
        foreach ($this->segments as $i => $seg) {
            $type = $seg['type'] ?? '';
            if ($type === 'added') {
                continue;
            }
            if ($type === 'context' && (int) $i > $lastChange) {
                continue;
            }
            $result[] = $seg;
        }
        return $result;
    }

    /** @return int Lines consumed from the original file for this hunk. */
    private function orig_lines_in_hunk(): int {
        if ($this->segments !== []) {
            return count($this->orig_file_segments());
        }
        return count($this->context) + count($this->removed);
    }
    
    /** @return array{canApply:bool, error:string|null} */
    public function canApplyTo($fileLines) {
        if ($this->origStart < 1) {
            return ['canApply' => false, 'error' => 'Invalid start line (must be >= 1)'];
        }

        $origLines = $this->orig_lines_in_hunk();
        if ($this->origStart - 1 + $origLines > count($fileLines)) {
            return [
                'canApply' => false,
                'error' => "Hunk starts at line {$this->origStart} but file has only " . count($fileLines) . " lines"
            ];
        }

        if ($this->segments !== []) {
            $idx = $this->origStart - 1;
            foreach ($this->orig_file_segments() as $seg) {
                if ($idx >= count($fileLines)) {
                    return ['canApply' => false, 'error' => 'Context mismatch: file too short'];
                }
                $expected = rtrim((string) ($seg['text'] ?? ''), "\r\n");
                $actual = rtrim($fileLines[$idx], "\r\n");
                if ($actual !== $expected) {
                    return [
                        'canApply' => false,
                        'error' => "Context mismatch at line " . ($idx + 1)
                    ];
                }
                $idx++;
            }
            return ['canApply' => true, 'error' => null];
        }
        
        $startIdx = $this->origStart - 1;
        foreach ($this->context as $i => $expectedLine) {
            if ($startIdx + $i >= count($fileLines)) {
                return ['canApply' => false, 'error' => 'Context mismatch: file too short'];
            }
            $expected = rtrim($expectedLine, "\r\n");
            $actual = rtrim($fileLines[$startIdx + $i], "\r\n");
            if ($actual !== $expected) {
                return [
                    'canApply' => false,
                    'error' => "Context mismatch at line " . ($this->origStart + $i)
                ];
            }
        }
        
        return ['canApply' => true, 'error' => null];
    }

    /** True when the file already reflects this hunk's post-patch content. */
    public function matchesPostImage($fileLines) {
        if ($this->newStart < 1) {
            return ['matches' => false, 'error' => 'Invalid new start line (must be >= 1)'];
        }

        $idx = $this->newStart - 1;
        if ($this->segments !== []) {
            foreach ($this->segments as $seg) {
                $type = $seg['type'] ?? '';
                if ($type === 'removed') {
                    continue;
                }
                if ($idx >= count($fileLines)) {
                    return ['matches' => false, 'error' => 'Post-image mismatch: file too short'];
                }
                $expected = rtrim((string) ($seg['text'] ?? ''), "\r\n");
                $actual = rtrim($fileLines[$idx], "\r\n");
                if ($actual !== $expected) {
                    return [
                        'matches' => false,
                        'error' => "Post-image mismatch at line " . ($idx + 1),
                    ];
                }
                $idx++;
            }
            return ['matches' => true, 'error' => null];
        }

        foreach ($this->context as $line) {
            if ($idx >= count($fileLines)) {
                return ['matches' => false, 'error' => 'Post-image mismatch: file too short'];
            }
            $expected = rtrim($line, "\r\n");
            $actual = rtrim($fileLines[$idx], "\r\n");
            if ($actual !== $expected) {
                return [
                    'matches' => false,
                    'error' => "Post-image mismatch at line " . ($idx + 1),
                ];
            }
            $idx++;
        }
        foreach ($this->added as $line) {
            if ($idx >= count($fileLines)) {
                return ['matches' => false, 'error' => 'Post-image mismatch: file too short'];
            }
            $expected = rtrim($line, "\r\n");
            $actual = rtrim($fileLines[$idx], "\r\n");
            if ($actual !== $expected) {
                return [
                    'matches' => false,
                    'error' => "Post-image mismatch at line " . ($idx + 1),
                ];
            }
            $idx++;
        }

        return ['matches' => true, 'error' => null];
    }

    /**
     * Re-anchor hunk line numbers by searching for the removed line + leading context.
     * Handles ingest_snapshot line drift when the live file gained or lost lines above the edit.
     */
    public function tryRelocateInFile($fileLines): bool {
        if ($this->canApplyTo($fileLines)['canApply']) {
            return true;
        }
        if ($this->segments === [] || $this->removed === []) {
            return false;
        }

        $leadingContext = [];
        foreach ($this->segments as $seg) {
            $type = $seg['type'] ?? '';
            if ($type === 'removed') {
                break;
            }
            if ($type === 'context') {
                $leadingContext[] = rtrim((string) ($seg['text'] ?? ''), "\r\n");
            }
        }

        $removedNeedle = rtrim((string) ($this->removed[0] ?? ''), "\r\n");
        if ($removedNeedle === '') {
            return false;
        }

        $ctxCount = count($leadingContext);
        $headerDelta = $this->newStart - $this->origStart;

        for ($i = 0; $i < count($fileLines); $i++) {
            if (rtrim($fileLines[$i], "\r\n") !== $removedNeedle) {
                continue;
            }
            $ctxStart = $i - $ctxCount;
            if ($ctxStart < 0) {
                continue;
            }
            $matched = true;
            for ($j = 0; $j < $ctxCount; $j++) {
                if (rtrim($fileLines[$ctxStart + $j], "\r\n") !== $leadingContext[$j]) {
                    $matched = false;
                    break;
                }
            }
            if (!$matched) {
                continue;
            }
            $savedOrig = $this->origStart;
            $savedNew = $this->newStart;
            $this->origStart = $ctxStart + 1;
            $this->newStart = $this->origStart + $headerDelta;
            if ($this->canApplyTo($fileLines)['canApply']) {
                return true;
            }
            $this->origStart = $savedOrig;
            $this->newStart = $savedNew;
        }

        return false;
    }
}

/** A patch for a single file, composed of one or more hunks. */
class Patcherly_FilePatch {
    public $filePath;
    public $hunks = [];
    
    public function __construct($filePath) {
        $this->filePath = $filePath;
    }
    
    public function addHunk($hunk) {
        $this->hunks[] = $hunk;
    }
    
    /** @return array{canApply:bool, error:string|null} */
    public function canApplyTo($filePath) {
        if (!file_exists($filePath)) {
            // Missing target is OK only if every hunk is pure additions.
            foreach ($this->hunks as $hunk) {
                if ($hunk->origLen > 0) {
                    return ['canApply' => false, 'error' => 'File does not exist and patch contains deletions'];
                }
            }
            return ['canApply' => true, 'error' => null];
        }

        $fileLines = [];
        try {
            $content = file_get_contents($filePath);
            if ($content === false) {
                return ['canApply' => false, 'error' => 'Cannot read file'];
            }
            $fileLines = explode("\n", $content);
            // Re-add trailing newlines, except on the final line if the file has no terminating newline.
            $fileLines = array_map(function($line, $idx, $arr) use ($content) {
                if ($idx < count($arr) - 1 || substr($content, -1) === "\n") {
                    return $line . "\n";
                }
                return $line;
            }, $fileLines, array_keys($fileLines), array_fill(0, count($fileLines), $fileLines));
        } catch (Exception $e) {
            return ['canApply' => false, 'error' => "Cannot read file: {$e->getMessage()}"];
        }

        foreach ($this->hunks as $i => $hunk) {
            if (!$hunk->canApplyTo($fileLines)['canApply']) {
                $hunk->tryRelocateInFile($fileLines);
            }
            $result = $hunk->canApplyTo($fileLines);
            if (!$result['canApply']) {
                return ['canApply' => false, 'error' => "Hunk " . ($i + 1) . ": {$result['error']}"];
            }
        }
        
        return ['canApply' => true, 'error' => null];
    }

    /** @return array{matches:bool, error:string|null} */
    public function matchesPostImage($filePath) {
        if (!file_exists($filePath)) {
            return ['matches' => false, 'error' => 'File does not exist'];
        }

        $fileLines = [];
        try {
            $content = file_get_contents($filePath);
            if ($content === false) {
                return ['matches' => false, 'error' => 'Cannot read file'];
            }
            $fileLines = explode("\n", $content);
            $fileLines = array_map(function($line, $idx, $arr) use ($content) {
                if ($idx < count($arr) - 1 || substr($content, -1) === "\n") {
                    return $line . "\n";
                }
                return $line;
            }, $fileLines, array_keys($fileLines), array_fill(0, count($fileLines), $fileLines));
        } catch (Exception $e) {
            return ['matches' => false, 'error' => "Cannot read file: {$e->getMessage()}"];
        }

        foreach ($this->hunks as $i => $hunk) {
            $result = $hunk->matchesPostImage($fileLines);
            if (!$result['matches']) {
                return ['matches' => false, 'error' => "Hunk " . ($i + 1) . ": {$result['error']}"];
            }
        }

        return ['matches' => true, 'error' => null];
    }
}

class Patcherly_PatchApplicator {
    public function __construct() {}

    /** True iff $filePath resolves inside ABSPATH (strict path-segment boundary, no sibling-prefix matches). */
    private function is_path_safe($filePath) {
        $abspath = ABSPATH;
        $realPath = realpath($filePath);
        $realAbspath = realpath($abspath);

        if ($realPath === false || $realAbspath === false) {
            return false;
        }

        $sep = DIRECTORY_SEPARATOR;
        $abs = rtrim($realAbspath, $sep);
        $prefix = $abs . $sep;
        return $realPath === $abs || strpos($realPath, $prefix) === 0;
    }

    /** Parse unified diff text into FilePatch objects. Throws Patcherly_PatchParseError on malformed input. */
    public function parsePatch($patchText) {
        $filePatches = [];
        $lines = explode("\n", $patchText);
        
        $i = 0;
        while ($i < count($lines)) {
            // Look for file header: --- a/path
            if (strpos($lines[$i], '---') === 0) {
                if (preg_match('/^---\s+a\/(.+)$/', $lines[$i], $matches) ||
                    preg_match('/^---\s+(.+)$/', $lines[$i], $matches)) {
                    $filePath = trim($matches[1]);
                    
                    // Skip to +++ line
                    $i++;
                    if ($i >= count($lines) || strpos($lines[$i], '+++') !== 0) {
                        throw new Patcherly_PatchParseError(esc_html("Missing +++ line after --- for {$filePath}"));
                    }
                    
                    // Create FilePatch
                    $filePatch = new Patcherly_FilePatch($filePath);
                    
                    // Parse hunks
                    $i++;
                    while ($i < count($lines)) {
                        $line = $lines[$i];
                        
                        // Empty line between hunks
                        if (!trim($line)) {
                            $i++;
                            continue;
                        }
                        
                        // New file header - done with this file
                        if (strpos($line, '---') === 0) {
                            break;
                        }
                        
                        // Hunk header: @@ -orig_start,orig_len +new_start,new_len @@
                        if (strpos($line, '@@') === 0) {
                            list($hunk, $i) = $this->parseHunk($lines, $i);
                            $filePatch->addHunk($hunk);
                            continue;
                        }
                        
                        $i++;
                    }
                    
                    $filePatches[] = $filePatch;
                } else {
                    $i++;
                }
            } else {
                $i++;
            }
        }
        
        if (empty($filePatches)) {
            throw new Patcherly_PatchParseError('No file patches found in patch text');
        }
        
        return $filePatches;
    }
    
    /** Parse one hunk starting at $startIdx; returns [Hunk, next_index]. */
    private function parseHunk($lines, $startIdx) {
        $hunkHeader = rtrim($lines[$startIdx], "\r\n");

        // Optional trailing text after the second @@ is valid unified-diff (git style).
        if (!preg_match('/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/', $hunkHeader, $matches)) {
            throw new Patcherly_PatchParseError(esc_html("Invalid hunk header: {$hunkHeader}"));
        }
        
        $origStart = intval($matches[1]);
        $origLen = intval($matches[2] ?? 1);
        $newStart = intval($matches[3]);
        $newLen = intval($matches[4] ?? 1);
        
        $context = [];
        $removed = [];
        $added = [];
        $segments = [];

        $i = $startIdx + 1;
        while ($i < count($lines)) {
            $line = $lines[$i];

            if (strpos($line, '@@') === 0 || strpos($line, '---') === 0) {
                break;
            }

            if (strpos($line, ' ') === 0) {
                $text = substr($line, 1);
                $context[] = $text;
                $segments[] = ['type' => 'context', 'text' => $text];
            } elseif (strpos($line, '-') === 0) {
                $text = substr($line, 1);
                $removed[] = $text;
                $segments[] = ['type' => 'removed', 'text' => $text];
            } elseif (strpos($line, '+') === 0) {
                $text = substr($line, 1);
                $added[] = $text;
                $segments[] = ['type' => 'added', 'text' => $text];
            } elseif (trim($line) === '') {
                $context[] = '';
                $segments[] = ['type' => 'context', 'text' => ''];
            }

            $i++;
        }

        return [new Patcherly_Hunk($origStart, $origLen, $newStart, $newLen, $context, $removed, $added, $segments), $i];
    }

    /**
     * Apply a FilePatch under an advisory lock with optional PHP syntax verification + auto-rollback.
     *
     * @return array{success:bool, message:string, syntaxErrors:array|null}
     */
    public function applyPatch($filePatch, $filePath, $dryRun = false, $verifySyntax = true) {
        if (!$this->is_path_safe($filePath)) {
            return [
                'success' => false,
                'message' => 'File path is not safe (outside WordPress root)',
                'syntaxErrors' => null
            ];
        }

        $canApply = $filePatch->canApplyTo($filePath);
        if (!$canApply['canApply']) {
            $already = $filePatch->matchesPostImage($filePath);
            if (!empty($already['matches'])) {
                return [
                    'success' => true,
                    'message' => "Patch already applied to {$filePath}",
                    'syntaxErrors' => null,
                ];
            }
            return [
                'success' => false,
                'message' => "Cannot apply patch: {$canApply['error']}",
                'syntaxErrors' => null
            ];
        }
        
        if ($dryRun) {
            return [
                'success' => true,
                'message' => "Dry-run: Patch would be applied successfully to {$filePath}",
                'syntaxErrors' => null
            ];
        }

        $lock = new Patcherly_FileLock($filePath);
        try {
            $lock->acquire();

            $originalLines = [];
            if (file_exists($filePath)) {
                $content = file_get_contents($filePath);
                if ($content !== false) {
                    $originalLines = explode("\n", $content);
                    $originalLines = array_map(function($line, $idx, $arr) use ($content) {
                        if ($idx < count($arr) - 1 || substr($content, -1) === "\n") {
                            return $line . "\n";
                        }
                        return $line;
                    }, $originalLines, array_keys($originalLines), array_fill(0, count($originalLines), $originalLines));
                }
            }

            // Apply hunks in reverse order so line numbers remain valid as we mutate.
            $modifiedLines = $originalLines;
            usort($filePatch->hunks, function($a, $b) {
                return $b->origStart - $a->origStart;
            });

            foreach ($filePatch->hunks as $hunk) {
                $modifiedLines = $this->applyHunk($hunk, $modifiedLines);
            }

            $content = implode('', $modifiedLines);
            file_put_contents($filePath, $content);

            $syntaxErrors = null;
            if ($verifySyntax) {
                $syntaxOk = $this->verifySyntax($filePath);
                if (!$syntaxOk['valid']) {
                    file_put_contents($filePath, implode('', $originalLines));
                    $lock->release();
                    return [
                        'success' => false,
                        'message' => 'Syntax validation failed',
                        'syntaxErrors' => $syntaxOk['errors']
                    ];
                }
                $syntaxErrors = $syntaxOk['errors'] ?? [];
            }
            
            $lock->release();
            
            return [
                'success' => true,
                'message' => "Patch applied successfully to {$filePath}",
                'syntaxErrors' => $syntaxErrors
            ];
        } catch (Patcherly_PatchApplyError $e) {
            $lock->release();
            return [
                'success' => false,
                'message' => $e->getMessage(),
                'syntaxErrors' => null
            ];
        } catch (Exception $e) {
            $lock->release();
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log("Patcherly PatchApplicator: Error applying patch: {$e->getMessage()}");
            }
            return [
                'success' => false,
                'message' => "Error applying patch: {$e->getMessage()}",
                'syntaxErrors' => null
            ];
        }
    }
    
    private function line_with_newline($line) {
        return (substr($line, -1) === "\n") ? $line : ($line . "\n");
    }

    private function applyHunk($hunk, $fileLines) {
        $startIdx = $hunk->origStart - 1;

        if (!empty($hunk->segments)) {
            $result = array_slice($fileLines, 0, $startIdx);
            $origConsumed = 0;
            $trailingDecorative = [];
            $lastChange = -1;
            foreach ($hunk->segments as $i => $seg) {
                $type = $seg['type'] ?? '';
                if ($type === 'added' || $type === 'removed') {
                    $lastChange = (int) $i;
                }
            }
            foreach ($hunk->segments as $i => $seg) {
                $type = $seg['type'] ?? '';
                $text = (string) ($seg['text'] ?? '');
                if ($type === 'context') {
                    if ((int) $i > $lastChange) {
                        $trailingDecorative[] = $text;
                        continue;
                    }
                    $result[] = $this->line_with_newline($text);
                    $origConsumed++;
                } elseif ($type === 'removed') {
                    $origConsumed++;
                } elseif ($type === 'added') {
                    $result[] = $this->line_with_newline($text);
                }
            }
            $remainingStart = $startIdx + $origConsumed;
            if ($remainingStart < count($fileLines)) {
                $result = array_merge($result, array_slice($fileLines, $remainingStart));
            } elseif ($trailingDecorative !== []) {
                foreach ($trailingDecorative as $text) {
                    $result[] = $this->line_with_newline($text);
                }
            }
            return $result;
        }

        $linesToRemove = count($hunk->context) + count($hunk->removed);
        $result = array_slice($fileLines, 0, $startIdx);
        
        // Add context + new lines
        foreach ($hunk->context as $line) {
            $result[] = $this->line_with_newline($line);
        }
        
        foreach ($hunk->added as $line) {
            $result[] = $this->line_with_newline($line);
        }
        
        // Add remaining lines
        $remainingStart = $startIdx + $linesToRemove;
        if ($remainingStart < count($fileLines)) {
            $result = array_merge($result, array_slice($fileLines, $remainingStart));
        }
        
        return $result;
    }
    
    /**
     * Validate PHP syntax via TOKEN_PARSE — no shell, no eval. Non-PHP files are reported as valid.
     *
     * @return array{valid:bool, errors:array}
     */
    private function verifySyntax($filePath) {
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        if ($ext !== 'php' && $ext !== 'phtml') {
            return ['valid' => true, 'errors' => []];
        }

        try {
            $code = @file_get_contents($filePath);
            if ($code === false) {
                return [
                    'valid' => false,
                    'errors' => ['Could not read file for syntax validation']
                ];
            }
            token_get_all($code, TOKEN_PARSE);
            return ['valid' => true, 'errors' => []];
        } catch (ParseError $e) {
            return [
                'valid' => false,
                'errors' => ["Syntax parse error: {$e->getMessage()}"]
            ];
        } catch (Exception $e) {
            return [
                'valid' => false,
                'errors' => ["Syntax check error: {$e->getMessage()}"]
            ];
        }
    }
}

