"""
Python Context Collector

Collects environment information for AI analysis:
- Python version and environment
- Installed packages
- System information
- Framework detection (Django, Flask, FastAPI, etc.)
- Database connections
- Environment variables (sanitized)
"""

import json
import sys
import platform
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime


class PythonContextCollector:
    """Collects context information for Python applications."""
    
    def __init__(self, cache_dir: Optional[str] = None):
        """Initialize collector with cache directory.
        Uses PATCHERLY_CACHE_DIR or APR_CACHE_DIR env if cache_dir not provided.
        """
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            # PATCHERLY_* preferred; APR_* for backward compatibility
            default = os.getenv('PATCHERLY_CACHE_DIR') or os.getenv('APR_CACHE_DIR') or '.patcherly_cache'
            # IMPORTANT: For web deployments, ensure this is outside webroot
            self.cache_dir = Path(default)
        
        # Create cache directory if it doesn't exist
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure cache directory is protected (create .htaccess for Apache, .nginx for Nginx)
        self._ensure_cache_protection()
    
    def collect_all(self) -> Dict[str, Any]:
        """Collect all context information."""
        return {
            'server': self.collect_server_info(),
            'python': self.collect_python_info(),
            'packages': self.collect_packages(),
            'framework': self.detect_framework(),
            'database': self.detect_database(),
            'environment': self.collect_environment(),
            'collected_at': datetime.now().isoformat(),
        }
    
    def collect_server_info(self) -> Dict[str, Any]:
        """Collect server/system information."""
        return {
            'os': platform.system(),
            'os_version': platform.version(),
            'platform': platform.platform(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'hostname': platform.node(),
        }
    
    def collect_python_info(self) -> Dict[str, Any]:
        """Collect Python version and environment information."""
        return {
            'version': sys.version,
            'version_info': {
                'major': sys.version_info.major,
                'minor': sys.version_info.minor,
                'micro': sys.version_info.micro,
            },
            'executable': sys.executable,
            'platform': sys.platform,
            'implementation': platform.python_implementation(),
        }
    
    def collect_packages(self) -> List[Dict[str, str]]:
        """Collect installed Python packages."""
        packages = []
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'list', '--format=json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                packages_data = json.loads(result.stdout)
                packages = [
                    {
                        'name': pkg.get('name', ''),
                        'version': pkg.get('version', ''),
                    }
                    for pkg in packages_data
                ]
        except Exception:
            # If pip list fails, try alternative method
            try:
                import pkg_resources
                packages = [
                    {
                        'name': dist.project_name,
                        'version': dist.version,
                    }
                    for dist in pkg_resources.working_set
                ]
            except Exception:
                pass
        
        return packages
    
    def detect_framework(self) -> Dict[str, Any]:
        """Detect which web framework is being used."""
        framework_info = {
            'detected': None,
            'version': None,
        }
        
        # Check for Django
        try:
            import django
            framework_info['detected'] = 'django'
            framework_info['version'] = django.get_version()
            framework_info['settings_module'] = os.environ.get('DJANGO_SETTINGS_MODULE')
        except ImportError:
            pass
        
        # Check for Flask
        try:
            import flask
            framework_info['detected'] = 'flask'
            framework_info['version'] = flask.__version__
        except ImportError:
            pass
        
        # Check for FastAPI
        try:
            import fastapi
            framework_info['detected'] = 'fastapi'
            framework_info['version'] = fastapi.__version__
        except ImportError:
            pass
        
        # Check for Pyramid
        try:
            import pyramid
            framework_info['detected'] = 'pyramid'
            framework_info['version'] = pyramid.__version__
        except ImportError:
            pass
        
        return framework_info
    
    def detect_database(self) -> Dict[str, Any]:
        """Detect database connections."""
        databases = {}
        
        # Check for common database libraries
        db_checks = [
            ('psycopg2', 'postgresql'),
            ('pymongo', 'mongodb'),
            ('mysql', 'mysql'),
            ('sqlite3', 'sqlite'),
        ]
        
        for module_name, db_type in db_checks:
            try:
                __import__(module_name)
                databases[db_type] = {'available': True}
            except ImportError:
                databases[db_type] = {'available': False}
        
        return databases
    
    def collect_environment(self) -> Dict[str, Any]:
        """Collect environment variables (sanitized - no secrets)."""
        # List of environment variable keys that might contain secrets
        secret_keys = [
            'password', 'secret', 'key', 'token', 'api_key', 'apikey',
            'auth', 'credential', 'private', 'access', 'refresh'
        ]
        
        env_vars = {}
        for key, value in os.environ.items():
            # Skip variables that look like secrets
            key_lower = key.lower()
            if any(secret in key_lower for secret in secret_keys):
                env_vars[key] = '[REDACTED]'
            else:
                env_vars[key] = value
        
        return env_vars
    
    def save_context(self) -> bool:
        """Save context to JSON files."""
        context = self.collect_all()
        
        # Save full context
        full_context_file = self.cache_dir / 'python-context.json'
        try:
            with open(full_context_file, 'w') as f:
                json.dump(context, f, indent=2)
        except Exception:
            return False
        
        # Save server context separately
        server_context = {
            'server': context['server'],
            'collected_at': context['collected_at'],
        }
        server_context_file = self.cache_dir / 'server-context.json'
        try:
            with open(server_context_file, 'w') as f:
                json.dump(server_context, f, indent=2)
        except Exception:
            return False
        
        return True
    
    def load_context(self) -> Optional[Dict[str, Any]]:
        """Load context from JSON files."""
        context_file = self.cache_dir / 'python-context.json'
        if not context_file.exists():
            return None
        
        try:
            with open(context_file, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    
    def has_changed(self) -> bool:
        """Check if context has changed since last collection."""
        old_context = self.load_context()
        if not old_context:
            return True
        
        new_context = self.collect_all()
        
        # Compare key fields
        key_fields = ['packages', 'framework', 'database']
        
        for field in key_fields:
            old_value = old_context.get(field)
            new_value = new_context.get(field)
            
            if json.dumps(old_value, sort_keys=True) != json.dumps(new_value, sort_keys=True):
                return True
        
        return False
    
    def _ensure_cache_protection(self):
        """Ensure cache directory is protected from direct web access."""
        # Create .htaccess for Apache
        htaccess_file = self.cache_dir / '.htaccess'
        if not htaccess_file.exists():
            try:
                with open(htaccess_file, 'w') as f:
                    f.write("# Deny all direct access to context files\n")
                    f.write("Order Deny,Allow\n")
                    f.write("Deny from all\n")
                    f.write("\n# Prevent directory listing\n")
                    f.write("Options -Indexes\n")
            except Exception:
                pass  # May not have write permissions or not Apache
        
        # Create .nginx for Nginx (if using Nginx)
        nginx_file = self.cache_dir / '.nginx'
        if not nginx_file.exists():
            try:
                with open(nginx_file, 'w') as f:
                    f.write("# Nginx configuration snippet\n")
                    f.write("# Add to your Nginx server block:\n")
                    f.write("# location ~ ^/.apr_cache/ {\n")
                    f.write("#     deny all;\n")
                    f.write("#     return 403;\n")
                    f.write("# }\n")
            except Exception:
                pass
        
        # Create index.html to prevent directory listing
        index_file = self.cache_dir / 'index.html'
        if not index_file.exists():
            try:
                with open(index_file, 'w') as f:
                    f.write("<!-- Directory listing disabled -->\n")
            except Exception:
                pass

