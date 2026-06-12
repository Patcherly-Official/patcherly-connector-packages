<?php
/**
 * Parse and apply unified-diff patches with WordPress-aware path containment and locking.
 */

if (!defined('ABSPATH')) { exit; }

class Patcherly_PatchParseError extends Exception {
}

class Patcherly_PatchApplyError extends Exception {
}

class Patcherly_FileLock {
    /**
     * Advisory file lock using a sha1-keyed sidecar in wp-content/uploads/patcherly_locks/.
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
        $upload = function_exists('wp_upload_dir') ? wp_upload_dir(null, false) : ['basedir' => sys_get_temp_dir()];
        $base = isset($upload['basedir']) && is_string($upload['basedir']) && $upload['basedir'] !== ''
            ? $upload['basedir']
            : sys_get_temp_dir();
        $dir = trailingslashit($base) . 'patcherly_locks';
        self::ensure_lock_dir_protection($dir);
        return $dir . '/' . sha1($filePath) . '.lock';
    }

    /** Idempotently create the locks dir and install .htaccess + web.config + index.php deny rules. */
    private static function ensure_lock_dir_protection(string $dir): void {
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
    
    public function __construct($origStart, $origLen, $newStart, $newLen, $context, $removed, $added) {
        $this->origStart = $origStart;
        $this->origLen = $origLen;
        $this->newStart = $newStart;
        $this->newLen = $newLen;
        $this->context = $context;
        $this->removed = $removed;
        $this->added = $added;
    }
    
    /** @return array{canApply:bool, error:string|null} */
    public function canApplyTo($fileLines) {
        if ($this->origStart < 1) {
            return ['canApply' => false, 'error' => 'Invalid start line (must be >= 1)'];
        }

        if ($this->origStart - 1 + count($this->context) > count($fileLines)) {
            return [
                'canApply' => false,
                'error' => "Hunk starts at line {$this->origStart} but file has only " . count($fileLines) . " lines"
            ];
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
            $result = $hunk->canApplyTo($fileLines);
            if (!$result['canApply']) {
                return ['canApply' => false, 'error' => "Hunk " . ($i + 1) . ": {$result['error']}"];
            }
        }
        
        return ['canApply' => true, 'error' => null];
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

        if (!preg_match('/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@$/', $hunkHeader, $matches)) {
            throw new Patcherly_PatchParseError(esc_html("Invalid hunk header: {$hunkHeader}"));
        }
        
        $origStart = intval($matches[1]);
        $origLen = intval($matches[2] ?? 1);
        $newStart = intval($matches[3]);
        $newLen = intval($matches[4] ?? 1);
        
        $context = [];
        $removed = [];
        $added = [];

        $i = $startIdx + 1;
        while ($i < count($lines)) {
            $line = $lines[$i];

            if (strpos($line, '@@') === 0 || strpos($line, '---') === 0) {
                break;
            }

            if (strpos($line, ' ') === 0) {
                $context[] = substr($line, 1);
            } elseif (strpos($line, '-') === 0) {
                $removed[] = substr($line, 1);
            } elseif (strpos($line, '+') === 0) {
                $added[] = substr($line, 1);
            } elseif (trim($line) === '') {
                $context[] = '';
            }

            $i++;
        }

        return [new Patcherly_Hunk($origStart, $origLen, $newStart, $newLen, $context, $removed, $added), $i];
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
    
    private function applyHunk($hunk, $fileLines) {
        $startIdx = $hunk->origStart - 1;

        $linesToRemove = count($hunk->context) + count($hunk->removed);
        $result = array_slice($fileLines, 0, $startIdx);
        
        // Add context + new lines
        foreach ($hunk->context as $line) {
            $result[] = (substr($line, -1) === "\n") ? $line : ($line . "\n");
        }
        
        foreach ($hunk->added as $line) {
            $result[] = (substr($line, -1) === "\n") ? $line : ($line . "\n");
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

