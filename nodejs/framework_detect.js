/**
 * Node.js framework detection for ingest + context upload.
 *
 * Prefer require.resolve when the app node_modules is resolvable; otherwise use
 * filesystem cues (package.json deps / node_modules) so a standalone agent can
 * stamp code_framework. Unknown stacks stay null (language-only).
 */

'use strict';

const fs = require('fs');
const path = require('path');

/** More specific frameworks before shared runtimes (Nest often depends on Express). */
const RUNTIME_PACKAGES = [
    { pkg: '@nestjs/core', label: 'nestjs' },
    { pkg: 'next', label: 'nextjs' },
    { pkg: 'koa', label: 'koa' },
    { pkg: 'express', label: 'express' },
];

function frameworkFromRuntime() {
    for (const { pkg, label } of RUNTIME_PACKAGES) {
        try {
            require.resolve(pkg);
            return label;
        } catch (_) { /* not installed in this process */ }
    }
    return null;
}

function readPackageJson(root) {
    const file = path.join(root, 'package.json');
    if (!fs.existsSync(file)) return null;
    try {
        const raw = fs.readFileSync(file, 'utf8');
        const data = JSON.parse(raw);
        return data && typeof data === 'object' ? data : null;
    } catch (_) {
        return null;
    }
}

function packageJsonLists(root, packageName) {
    const pkg = readPackageJson(root);
    if (!pkg) return false;
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    return Object.prototype.hasOwnProperty.call(deps, packageName);
}

function nodeModulesHas(root, packageName) {
    // Scoped packages: @nestjs/core → node_modules/@nestjs/core
    const parts = packageName.split('/');
    return fs.existsSync(path.join(root, 'node_modules', ...parts));
}

function frameworkFromFilesystem(root) {
    if (!root || !fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
        return null;
    }
    for (const { pkg, label } of RUNTIME_PACKAGES) {
        if (packageJsonLists(root, pkg) || nodeModulesHas(root, pkg)) {
            return label;
        }
    }
    return null;
}

function rootsFromNodeModulesHint(hintPath) {
    const roots = [];
    if (!hintPath || typeof hintPath !== 'string') return roots;
    const norm = hintPath.replace(/\\/g, '/');
    const m = norm.match(/^(.*?)\/node_modules\//);
    if (m && m[1]) roots.push(m[1]);
    return roots;
}

function walkMarkerRoots(hintPath, maxUp = 8) {
    const roots = [];
    if (!hintPath || typeof hintPath !== 'string') return roots;
    let cur = path.dirname(path.resolve(hintPath));
    for (let i = 0; i < maxUp; i++) {
        if (!cur) break;
        if (fs.existsSync(path.join(cur, 'package.json'))) {
            roots.push(cur);
        }
        const parent = path.dirname(cur);
        if (parent === cur) break;
        cur = parent;
    }
    return roots;
}

function envTargetRoots() {
    const raw = process.env.PATCHERLY_TARGET_ROOTS || '';
    const sep = path.delimiter;
    return raw
        .replace(/;/g, sep)
        .split(sep)
        .map((p) => p.trim())
        .filter(Boolean);
}

function candidateRoots(hintPath) {
    const roots = [
        ...rootsFromNodeModulesHint(hintPath),
        ...walkMarkerRoots(hintPath),
        ...envTargetRoots(),
    ];
    try {
        const cwd = process.cwd();
        if (cwd) roots.push(cwd);
    } catch (_) { /* ignore */ }

    const seen = new Set();
    const ordered = [];
    for (const r of roots) {
        const key = path.resolve(r).replace(/\\/g, '/').toLowerCase();
        if (!key || seen.has(key)) continue;
        seen.add(key);
        ordered.push(r);
    }
    return ordered;
}

/**
 * @param {string|null|undefined} hintPath Optional throw-site path to infer app root.
 * @returns {string|null}
 */
function detectNodeFramework(hintPath) {
    const fromRt = frameworkFromRuntime();
    if (fromRt) return fromRt;
    for (const root of candidateRoots(hintPath || null)) {
        const fw = frameworkFromFilesystem(root);
        if (fw) return fw;
    }
    return null;
}

module.exports = {
    frameworkFromRuntime,
    frameworkFromFilesystem,
    candidateRoots,
    detectNodeFramework,
};
