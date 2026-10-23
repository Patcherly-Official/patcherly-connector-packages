<?php
/**
 * CLI: php connectors/php/tests/framework_detect_test.php
 *
 * Pins filesystem Laravel/Symfony detection for the standalone agent
 * (no app autoload / class_exists).
 */

require_once dirname(__DIR__) . '/framework_detect.php';

$failed = 0;

function expect_eq($label, $got, $want) {
    global $failed;
    if ($got !== $want) {
        fwrite(STDERR, "FAIL {$label}: got " . var_export($got, true) . " want " . var_export($want, true) . "\n");
        $failed++;
        return;
    }
    echo "OK {$label}\n";
}

$tmp = sys_get_temp_dir() . '/patcherly_fw_detect_' . bin2hex(random_bytes(4));
if (!mkdir($tmp, 0777, true)) {
    fwrite(STDERR, "Cannot create temp dir\n");
    exit(1);
}

try {
    // Laravel: artisan + composer require laravel/framework
    $laravel = $tmp . '/laravel_app';
    mkdir($laravel);
    file_put_contents($laravel . '/artisan', "#!/usr/bin/env php\n");
    file_put_contents(
        $laravel . '/composer.json',
        json_encode(['require' => ['laravel/framework' => '^11.0']], JSON_PRETTY_PRINT)
    );
    expect_eq(
        'laravel via artisan+composer',
        patcherly_php_framework_from_filesystem($laravel),
        'laravel'
    );

    // Laravel via vendor tree (no composer require needed when vendor present)
    $laravel2 = $tmp . '/laravel_vendor';
    mkdir($laravel2);
    file_put_contents($laravel2 . '/artisan', "#!/usr/bin/env php\n");
    mkdir($laravel2 . '/vendor/laravel/framework', 0777, true);
    expect_eq(
        'laravel via artisan+vendor',
        patcherly_php_framework_from_filesystem($laravel2),
        'laravel'
    );

    // Hint path under vendor → app root
    $roots = patcherly_php_framework_roots_from_path(
        $laravel2 . '/vendor/laravel/framework/src/Illuminate/Routing/Router.php'
    );
    expect_eq('root from vendor hint', $roots[0] ?? null, str_replace('\\', '/', $laravel2));

    expect_eq(
        'detect with hint path',
        patcherly_detect_php_framework(
            $laravel2 . '/vendor/laravel/framework/src/Illuminate/Routing/Router.php'
        ),
        'laravel'
    );

    // Empty / non-app dir
    $empty = $tmp . '/empty';
    mkdir($empty);
    expect_eq('empty root', patcherly_php_framework_from_filesystem($empty), null);

    // Parent walk from app code (no /vendor/ in path) + TARGET_ROOTS unused when walk hits
    mkdir($laravel . '/app');
    file_put_contents($laravel . '/app/Http.php', "<?php\n");
    expect_eq(
        'detect via parent walk',
        patcherly_detect_php_framework($laravel . '/app/Http.php'),
        'laravel'
    );
} finally {
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($tmp, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) {
        $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    }
    @rmdir($tmp);
}

if ($failed > 0) {
    fwrite(STDERR, "{$failed} failure(s)\n");
    exit(1);
}
echo "All framework_detect tests passed.\n";
exit(0);
