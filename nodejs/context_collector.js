/**
 * Node.js Context Collector
 * 
 * Collects environment information for AI analysis:
 * - Node.js version and environment
 * - Installed npm packages
 * - Framework detection (Express, Koa, NestJS, etc.)
 * - Database connections
 * - Environment variables (sanitized)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

class NodeJSContextCollector {
    constructor(cacheDir = null) {
        // PATCHERLY_* preferred; APR_* for backward compatibility
        this.cacheDir = cacheDir || process.env.PATCHERLY_CACHE_DIR || process.env.APR_CACHE_DIR || '.patcherly_cache';
        
        // Create cache directory if it doesn't exist
        if (!fs.existsSync(this.cacheDir)) {
            fs.mkdirSync(this.cacheDir, { recursive: true });
        }
        
        // Ensure cache directory is protected
        this.ensureCacheProtection();
    }
    
    /**
     * Ensure cache directory is protected from direct web access.
     */
    ensureCacheProtection() {
        const path = require('path');
        
        // Create .htaccess for Apache
        const htaccessFile = path.join(this.cacheDir, '.htaccess');
        if (!fs.existsSync(htaccessFile)) {
            try {
                const htaccessContent = 
                    "# Deny all direct access to context files\n" +
                    "Order Deny,Allow\n" +
                    "Deny from all\n" +
                    "\n# Prevent directory listing\n" +
                    "Options -Indexes\n";
                fs.writeFileSync(htaccessFile, htaccessContent);
            } catch (error) {
                // May not have write permissions or not Apache
            }
        }
        
        // Create .nginx for Nginx (if using Nginx)
        const nginxFile = path.join(this.cacheDir, '.nginx');
        if (!fs.existsSync(nginxFile)) {
            try {
                const nginxContent = 
                    "# Nginx configuration snippet\n" +
                    "# Add to your Nginx server block:\n" +
                    "# location ~ ^/.apr_cache/ {\n" +
                    "#     deny all;\n" +
                    "#     return 403;\n" +
                    "# }\n";
                fs.writeFileSync(nginxFile, nginxContent);
            } catch (error) {
                // May not have write permissions
            }
        }
        
        // Create index.html to prevent directory listing
        const indexFile = path.join(this.cacheDir, 'index.html');
        if (!fs.existsSync(indexFile)) {
            try {
                fs.writeFileSync(indexFile, "<!-- Directory listing disabled -->\n");
            } catch (error) {
                // May not have write permissions
            }
        }
    }
    
    /**
     * Collect all context information
     */
    collectAll() {
        return {
            server: this.collectServerInfo(),
            nodejs: this.collectNodeJSInfo(),
            packages: this.collectPackages(),
            framework: this.detectFramework(),
            database: this.detectDatabase(),
            environment: this.collectEnvironment(),
            collected_at: new Date().toISOString(),
        };
    }
    
    /**
     * Collect server information
     */
    collectServerInfo() {
        return {
            os: os.type(),
            os_version: os.release(),
            platform: os.platform(),
            architecture: os.arch(),
            hostname: os.hostname(),
            cpus: os.cpus().length,
            total_memory: os.totalmem(),
            free_memory: os.freemem(),
        };
    }
    
    /**
     * Collect Node.js information
     */
    collectNodeJSInfo() {
        return {
            version: process.version,
            versions: process.versions,
            platform: process.platform,
            arch: process.arch,
            exec_path: process.execPath,
        };
    }
    
    /**
     * Collect installed npm packages
     */
    collectPackages() {
        const packageJsonPath = path.join(process.cwd(), 'package.json');
        if (!fs.existsSync(packageJsonPath)) {
            return { available: false };
        }
        
        try {
            const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
            const packages = [];
            
            // Get dependencies
            if (packageJson.dependencies) {
                for (const [name, version] of Object.entries(packageJson.dependencies)) {
                    packages.push({ name, version_constraint: version, type: 'dependency' });
                }
            }
            
            // Get devDependencies
            if (packageJson.devDependencies) {
                for (const [name, version] of Object.entries(packageJson.devDependencies)) {
                    packages.push({ name, version_constraint: version, type: 'devDependency' });
                }
            }
            
            return {
                available: true,
                packages: packages,
            };
        } catch (error) {
            return {
                available: true,
                error: 'Failed to parse package.json',
            };
        }
    }
    
    /**
     * Detect which framework is being used
     */
    detectFramework() {
        const framework = {
            detected: null,
            version: null,
        };
        
        try {
            // Check for Express
            const expressPath = require.resolve('express');
            if (expressPath) {
                const expressPkg = require(path.join(path.dirname(expressPath), 'package.json'));
                framework.detected = 'express';
                framework.version = expressPkg.version;
            }
        } catch (e) {
            // Express not found
        }
        
        try {
            // Check for Koa
            const koaPath = require.resolve('koa');
            if (koaPath) {
                const koaPkg = require(path.join(path.dirname(koaPath), 'package.json'));
                framework.detected = 'koa';
                framework.version = koaPkg.version;
            }
        } catch (e) {
            // Koa not found
        }
        
        try {
            // Check for NestJS
            const nestjsPath = require.resolve('@nestjs/core');
            if (nestjsPath) {
                const nestjsPkg = require(path.join(path.dirname(nestjsPath), 'package.json'));
                framework.detected = 'nestjs';
                framework.version = nestjsPkg.version;
            }
        } catch (e) {
            // NestJS not found
        }
        
        try {
            // Check for Next.js
            const nextPath = require.resolve('next');
            if (nextPath) {
                const nextPkg = require(path.join(path.dirname(nextPath), 'package.json'));
                framework.detected = 'nextjs';
                framework.version = nextPkg.version;
            }
        } catch (e) {
            // Next.js not found
        }
        
        return framework;
    }
    
    /**
     * Detect database connections
     */
    detectDatabase() {
        const databases = {};
        
        // Check for common database libraries
        const dbChecks = [
            ['pg', 'postgresql'],
            ['mysql2', 'mysql'],
            ['mongodb', 'mongodb'],
            ['sqlite3', 'sqlite'],
        ];
        
        for (const [moduleName, dbType] of dbChecks) {
            try {
                require.resolve(moduleName);
                databases[dbType] = { available: true };
            } catch (e) {
                databases[dbType] = { available: false };
            }
        }
        
        return databases;
    }
    
    /**
     * Collect environment variables (sanitized - no secrets)
     */
    collectEnvironment() {
        const secretKeys = [
            'password', 'secret', 'key', 'token', 'api_key', 'apikey',
            'auth', 'credential', 'private', 'access', 'refresh'
        ];
        
        const envVars = {};
        for (const [key, value] of Object.entries(process.env)) {
            const keyLower = key.toLowerCase();
            if (secretKeys.some(secret => keyLower.includes(secret))) {
                envVars[key] = '[REDACTED]';
            } else {
                envVars[key] = value;
            }
        }
        
        return envVars;
    }
    
    /**
     * Save context to JSON files
     */
    saveContext() {
        const context = this.collectAll();
        
        // Save full context
        const fullContextFile = path.join(this.cacheDir, 'nodejs-context.json');
        try {
            fs.writeFileSync(fullContextFile, JSON.stringify(context, null, 2));
        } catch (error) {
            return false;
        }
        
        // Save server context separately
        const serverContext = {
            server: context.server,
            collected_at: context.collected_at,
        };
        const serverContextFile = path.join(this.cacheDir, 'server-context.json');
        try {
            fs.writeFileSync(serverContextFile, JSON.stringify(serverContext, null, 2));
        } catch (error) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Load context from JSON files
     */
    loadContext() {
        const contextFile = path.join(this.cacheDir, 'nodejs-context.json');
        if (!fs.existsSync(contextFile)) {
            return null;
        }
        
        try {
            const content = fs.readFileSync(contextFile, 'utf8');
            return JSON.parse(content);
        } catch (error) {
            return null;
        }
    }
    
    /**
     * Check if context has changed since last collection
     */
    hasChanged() {
        const oldContext = this.loadContext();
        if (!oldContext) {
            return true;
        }
        
        const newContext = this.collectAll();
        
        // Compare key fields
        const keyFields = ['packages', 'framework', 'database'];
        
        for (const field of keyFields) {
            const oldValue = oldContext[field];
            const newValue = newContext[field];
            
            if (JSON.stringify(oldValue) !== JSON.stringify(newValue)) {
                return true;
            }
        }
        
        return false;
    }
}

module.exports = NodeJSContextCollector;

