(function(){
  var cfg = window.PATCHERLY_SETTINGS || { url: '', key: '', tenantId: '', targetId: '', hmacEnabled: false, hmacSecret: '' };
  function $(id){ return document.getElementById(id); }
  function setText(el, t){ if(el) el.textContent = t; }
  function headerObj(){ var h={}; if (cfg.key) h['X-API-Key']=cfg.key; return h; }
  
  // WordPress plugin uses server-side HMAC signing via PHP backend
  // The JavaScript calls go through WordPress which handles HMAC signing

  function initStatus(){ if (window.PatcherlyStatus) window.PatcherlyStatus.init('patcherly', cfg.url, cfg.key); }

  async function testConnection(e){
    if(e) e.preventDefault();
    if(!cfg.url){ setText($('patcherly-test-result'),'Missing APR URL'); return false; }
    setText($('patcherly-test-result'),'Testing…');
    try {
      // Use WordPress backend for HMAC signing instead of direct API call
      var endpoint = cfg.key ? 'connector-status' : 'health-summary';
      var r = await fetch(ajaxurl + '?action=patcherly_test_connection&endpoint=' + endpoint, { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if(!r.ok) throw new Error('HTTP '+r.status);
      var j = await r.json();
      var dbt = (j.database_type) || '';
      var deploy = (j.deployment_type) || '';
      setText($('patcherly-test-result'), 'OK' + ((dbt||deploy)?(' ('+ [dbt&&('db='+dbt), deploy&&('deploy='+deploy)].filter(Boolean).join(', ') +')') : ''));
      if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
    } catch(e){ setText($('patcherly-test-result'),'Failed: '+(e&&e.message?e.message:'error')); }
    return false;
  }

  async function sendSample(e){
    if(e) e.preventDefault();
    if(!cfg.url){ setText($('patcherly-sample-result'),'Missing APR URL'); return false; }
    if(!cfg.key){ setText($('patcherly-sample-result'),'Missing Agent API Key'); return false; }
    setText($('patcherly-sample-result'),'Sending…');
    try{
      // Use WordPress AJAX handler which handles HMAC signing and proper endpoint construction
      var r = await fetch(ajaxurl + '?action=patcherly_send_sample', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if(!r.ok) {
        var errorData = await r.json().catch(function(){ return {}; });
        var errorMsg = errorData.data && errorData.data.error ? errorData.data.error : ('HTTP ' + r.status);
        throw new Error(errorMsg);
      }
      var result = await r.json();
      if (result.success) {
        setText($('patcherly-sample-result'), result.data && result.data.message ? result.data.message : 'Ingested successfully');
        if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
      } else {
        throw new Error(result.data && result.data.error ? result.data.error : 'Unknown error');
      }
    }catch(e){ setText($('patcherly-sample-result'),'Failed: '+(e&&e.message?e.message:'error')); }
    return false;
  }

  function bind(){
    var t = $('patcherly-form-test'); if (t) t.addEventListener('submit', testConnection);
    var s = $('patcherly-form-sample'); if (s) s.addEventListener('submit', sendSample);
    
    // Force Resync button
    var resyncBtn = $('patcherly-btn-force-resync');
    if (resyncBtn) {
      resyncBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        setText($('patcherly-resync-result'), 'Resyncing…');
        try {
          var r = await fetch(ajaxurl + '?action=patcherly_force_resync', { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (!r.ok) throw new Error('HTTP ' + r.status);
          var j = await r.json();
          
          if (j.success === false) {
            if (j.step === 'need_login' && j.show_login) {
              showLoginForm(j.message);
              setText($('patcherly-resync-result'), 'Login required');
            } else {
              setText($('patcherly-resync-result'), 'Failed: ' + (j.message || 'Unknown error'));
            }
          } else {
            setText($('patcherly-resync-result'), 'Resync completed successfully');
            // Refresh the status display
            if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
          }
        } catch(e) {
          setText($('patcherly-resync-result'), 'Failed: ' + (e.message || 'error'));
        }
      });
    }
    
    // Login form handlers
    var loginBtn = $('patcherly-btn-login');
    if (loginBtn) {
      loginBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        var username = $('patcherly-login-username').value;
        var password = $('patcherly-login-password').value;
        
        if (!username || !password) {
          setText($('patcherly-login-result'), 'Please enter username and password');
          return;
        }
        
        setText($('patcherly-login-result'), 'Logging in…');
        try {
          var fd = new FormData();
          fd.set('action', 'patcherly_jwt_login');
          fd.set('username', username);
          fd.set('password', password);
          
          var r = await fetch(ajaxurl, { method: 'POST', body: fd });
          if (!r.ok) throw new Error('HTTP ' + r.status);
          var j = await r.json();
          
          if (j.success === false) {
            var errorMsg = 'Login failed';
            if (j.error) {
              errorMsg += ': ' + j.error;
            }
            if (j.error_type) {
              errorMsg += ' (' + j.error_type + ')';
            }
            if (j.endpoint) {
              errorMsg += ' - Endpoint: ' + j.endpoint;
            }
            if (j.http_code) {
              errorMsg += ' - HTTP ' + j.http_code;
            }
            setText($('patcherly-login-result'), errorMsg);
          } else {
            setText($('patcherly-login-result'), 'Login successful! Agent key synced.');
            // Reflect saved credentials for current session UI
            try { cfg.savedUsername = username; cfg.savedPassword = '***saved***'; } catch(_){ }
            hideLoginForm();
            // Refresh the status display
            if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
          }
        } catch(e) {
          setText($('patcherly-login-result'), 'Login failed: ' + (e.message || 'error'));
        }
      });
    }
    
    var cancelBtn = $('patcherly-btn-cancel-login');
    if (cancelBtn) {
      cancelBtn.addEventListener('click', function(e) {
        e.preventDefault();
        hideLoginForm();
      });
    }
    
    // Use Saved Credentials button
    var useSavedBtn = $('patcherly-btn-use-saved');
    if (useSavedBtn) {
      useSavedBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        setText($('patcherly-login-result'), 'Using saved credentials...');
        
        try {
          var fd = new FormData();
          fd.set('action', 'patcherly_jwt_login');
          fd.set('use_saved', 'true');
          
          var r = await fetch(ajaxurl, { method: 'POST', body: fd });
          if (!r.ok) throw new Error('HTTP ' + r.status);
          var j = await r.json();
          
          if (j.success === false) {
            var errorMsg = 'Login failed';
            if (j.error) {
              errorMsg += ': ' + j.error;
            }
            if (j.error_type) {
              errorMsg += ' (' + j.error_type + ')';
            }
            if (j.endpoint) {
              errorMsg += ' - Endpoint: ' + j.endpoint;
            }
            if (j.http_code) {
              errorMsg += ' - HTTP ' + j.http_code;
            }
            setText($('patcherly-login-result'), errorMsg);
          } else {
            setText($('patcherly-login-result'), 'Login successful! Agent key synced.');
            hideLoginForm();
            // Refresh the status display
            if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
          }
        } catch(e) {
          setText($('patcherly-login-result'), 'Login failed: ' + (e.message || 'error'));
        }
      });
    }
    
    // Debug Endpoints button
    var debugBtn = $('patcherly-btn-debug-endpoints');
    if (debugBtn) {
      debugBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        try {
          var r = await fetch(ajaxurl + '?action=patcherly_debug_endpoints', { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (!r.ok) throw new Error('HTTP ' + r.status);
          var j = await r.json();
          
          var debugInfo = $('patcherly-debug-info');
          var debugContent = $('patcherly-debug-content');
          if (debugInfo && debugContent) {
            debugContent.textContent = JSON.stringify(j, null, 2);
            debugInfo.style.display = 'block';
          }
        } catch(e) {
          alert('Debug failed: ' + (e.message || 'error'));
        }
      });
    }
  }
  
  function showLoginForm(message) {
    var form = $('patcherly-login-form');
    if (form) {
      form.style.display = 'block';
      if (message) {
        var p = form.querySelector('p');
        if (p) p.textContent = message;
      }
      
      // Prefill saved credentials if available
      var username = $('patcherly-login-username');
      var password = $('patcherly-login-password');
      var result = $('patcherly-login-result');
      
      if (username && cfg.savedUsername) {
        username.value = cfg.savedUsername;
      }
      if (password) {
        password.value = ''; // Always clear password field for security
      }
      if (result) result.textContent = '';
      
      // Show "Use Saved Credentials" button if we have saved credentials
      var useSavedBtn = $('patcherly-btn-use-saved');
      if (useSavedBtn && cfg.savedUsername && cfg.savedPassword) {
        useSavedBtn.style.display = 'inline-block';
      } else if (useSavedBtn) {
        useSavedBtn.style.display = 'none';
      }
    }
  }
  
  function hideLoginForm() {
    var form = $('patcherly-login-form');
    if (form) {
      form.style.display = 'none';
    }
  }
  
  // Global function for status module to call
  window.Patcherly_ShowLogin = showLoginForm;

  if (document.readyState === 'complete') { initStatus(); bind(); }
  else { window.addEventListener('load', function(){ initStatus(); bind(); }); }
})();
