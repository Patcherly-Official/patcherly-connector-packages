(function(){
  if (window.PatcherlyStatus) return;
  function setText(el, text){ if(el) el.textContent = text; }
  function setHTML(el, html){ if(el) el.innerHTML = html; }

  window.PatcherlyStatus = {
    init: function(prefix, serverUrl, apiKey){
      var $ = function(id){ return document.getElementById(prefix + id); };
      var els = {
        api: $('-api-status'),
        deploy: $('-deploy'),
        db: $('-db'),
        hmac: $('-hmac'),
        key: $('-key'),
        tenant: $('-tenant'),
        target: $('-target'),
        targetName: $('-target-name'),
        meta: $('-status-meta'),
        btn: $('-status-refresh')
      };
      // Using WordPress Dashicons; no emoji normalization needed
      function headerObj(){ var h={}; if (apiKey) h['X-API-Key']=apiKey; return h; }
      var isRefreshing = false;
      async function refresh(){
        if (isRefreshing) return;
        isRefreshing = true;
        if (!serverUrl){ setText(els.meta, 'No Patcherly Server URL configured.'); return; }
        setText(els.meta, 'Connecting…');
        try{
          // Use smart connect for initial connection
          if (typeof ajaxurl !== 'undefined') {
            var r = await fetch(ajaxurl + '?action=patcherly_smart_connect', { 
              method: 'POST',
              headers: { 'Content-Type': 'application/json' }
            });
          } else {
            // Fallback to direct call (non-WordPress environments)
            var endpoint = serverUrl + '/api/targets/connector-status';
            var r = await fetch(endpoint, { headers: headerObj() });
          }
          if(!r.ok) throw new Error('HTTP '+r.status);
          var j = await r.json();
          
          // Handle smart connect response
          if (j.success === false) {
            if (j.step === 'need_login' && j.show_login) {
              handleLoginRequired(j.message);
              return;
            } else {
              throw new Error(j.message || 'Connection failed');
            }
          }
          
          // Success - use the data from smart connect
          var data = j.data || j;
          setHTML(els.api, data.api_ok ? ('Reachable <span class="dashicons dashicons-yes"></span>')
                                       : ('Unavailable <span class="dashicons dashicons-no"></span>'));
          setText(els.deploy, data.deployment_type || '—');
          setText(els.db, (data.database_type||'').toUpperCase());
          if (apiKey){
            var keyLine = (data.key_ok ? 'Valid <span class="dashicons dashicons-yes"></span>'
                                       : 'Invalid <span class="dashicons dashicons-no"></span>')
                          + (data.key_active === false ? ' (disabled)' : '');
            setHTML(els.key, keyLine);
            var tName = data.tenant_name ? (data.tenant_name + ' (id ' + data.tenant_id + ')') : (data.tenant_id ? ('ID ' + data.tenant_id) : '—');
            setText(els.tenant, tName + (data.tenant_status ? (' — ' + data.tenant_status) : ''));
            setText(els.target, data.target_id != null ? ('ID ' + data.target_id) : '—');
            setText(els.targetName, data.target_name ? String(data.target_name) : '');
            // HMAC status (table cell)
            try {
              if (typeof ajaxurl !== 'undefined'){
                fetch(ajaxurl + '?action=patcherly_hmac_status', { method:'POST' })
                  .then(function(r){ return r.json(); })
                  .then(function(x){
                    if (!els.hmac) return;
                    if (x && x.success && x.data){
                      var msg = x.data.enabled
                        ? ('Enabled ' + (x.data.has_secret ? '<span class="dashicons dashicons-yes"></span>'
                                                           : '<span class="dashicons dashicons-no"></span>'))
                        : 'Disabled <span class="dashicons dashicons-no"></span>';
                      if (x.data.enabled && x.data.required) msg += ' (required)';
                      setHTML(els.hmac, msg);
                    } else {
                      setText(els.hmac, 'Unknown');
                    }
                  });
              } else {
                var msg2 = (data.hmac_enabled && data.hmac_secret_present)
                  ? 'Enabled <span class="dashicons dashicons-yes"></span>'
                  : 'Disabled <span class="dashicons dashicons-no"></span>';
                if (els.hmac) setHTML(els.hmac, msg2);
              }
            } catch(_){ if (els.hmac) setText(els.hmac, 'Unknown'); }
            // cache ids globally for other modules
            window.__PATCHERLY_TENANT_ID__ = (data.tenant_id != null ? String(data.tenant_id) : (window.__PATCHERLY_TENANT_ID__||null));
            window.__PATCHERLY_TARGET_ID__ = (data.target_id != null ? String(data.target_id) : (window.__PATCHERLY_TARGET_ID__||null));
            window.__PATCHERLY_CURRENT_TARGET_ID__ = window.__PATCHERLY_TARGET_ID__;
            try{
              if (typeof ajaxurl !== 'undefined' && (data.tenant_id != null || data.target_id != null)){
                var fd = new FormData();
                fd.set('action','patcherly_save_ids');
                if (data.tenant_id != null) fd.set('tenant_id', String(data.tenant_id));
                if (data.target_id != null) fd.set('target_id', String(data.target_id));
                await fetch(ajaxurl, { method:'POST', body: fd });
              }
            }catch(_){ }
          } else {
            setText(els.key, 'Not configured');
            setText(els.tenant, '—');
            setText(els.target, '—');
            setText(els.targetName, '');
          }
          var successMsg = 'Connected successfully';
          if (j.step === 'connected' && j.message) {
            successMsg = j.message;
          }
          setText(els.meta, successMsg + ' at ' + (new Date()).toLocaleString());
        }catch(e){
          setText(els.api, 'Unavailable');
          setText(els.deploy, '—');
          setText(els.db, '—');
          setText(els.key, apiKey ? 'Unknown (check failed)' : 'Not configured');
          setText(els.tenant, '—');
          setText(els.target, '—');
          setText(els.targetName, '');
          
          // Provide more specific error messages based on the type of failure
          let errorMsg = 'Check failed';
          if (e && e.message) {
            if (e.message.includes('503')) {
              errorMsg = 'Service unavailable';
            } else if (e.message.includes('502')) {
              errorMsg = 'Bad gateway';
            } else if (e.message.includes('504')) {
              errorMsg = 'Gateway timeout';
            } else if (e.message.includes('Failed to fetch') || e.message.includes('NetworkError')) {
              errorMsg = 'Connection failed';
            } else {
              errorMsg = e.message;
            }
          }
          setText(els.meta, 'Check failed at ' + (new Date()).toLocaleString() + ': ' + errorMsg);
        } finally { isRefreshing = false; }
      }
      function handleLoginRequired(message) {
        setText(els.api, 'Login Required');
        setText(els.deploy, '—');
        setText(els.db, '—');
        setText(els.key, 'Not configured');
        setText(els.tenant, '—');
        setText(els.target, '—');
        setText(els.targetName, '');
        setText(els.meta, message || 'Login required to sync credentials');
        
        // Show login form if we're on the settings page
        if (typeof window.Patcherly_ShowLogin === 'function') {
          window.Patcherly_ShowLogin(message);
        }
      }
      
      if (els.btn){ els.btn.addEventListener('click', function(ev){ ev.preventDefault(); refresh(); }); }
      // Trigger initial refresh even if init runs after window load
      if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setTimeout(refresh, 150);
      } else {
        window.addEventListener('load', function(){ setTimeout(refresh, 150); });
      }
      if (!window.__PATCHERLY_STATUS__) window.__PATCHERLY_STATUS__ = {};
      window.__PATCHERLY_STATUS__[prefix] = { refresh };
    },
    refresh: function(prefix){ if (window.__PATCHERLY_STATUS__ && window.__PATCHERLY_STATUS__[prefix]) window.__PATCHERLY_STATUS__[prefix].refresh(); }
  };
})();


