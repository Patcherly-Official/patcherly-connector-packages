(function(){
  if (window.PatcherlyStatus) return;
  function setText(el, text){ if(el) el.textContent = text; }
  function setHTML(el, html){ if(el) el.innerHTML = html; }

  window.PatcherlyStatus = {
    init: function(prefix, serverUrl){
      var $ = function(id){ return document.getElementById(prefix + id); };
      var els = {
        api:        $('-api-status'),
        deploy:     $('-deploy'),
        db:         $('-db'),
        hmac:       $('-hmac'),
        key:        $('-key'),
        tenant:     $('-tenant'),
        target:     $('-target'),
        targetName: $('-target-name'),
        meta:       $('-status-meta'),
        btn:        $('-status-refresh')
      };
      var isRefreshing = false;

      async function refresh(){
        if (isRefreshing) return;
        isRefreshing = true;
        if (!serverUrl){ setText(els.meta, 'No Patcherly Server URL configured.'); isRefreshing = false; return; }
        setText(els.meta, 'Connecting…');
        try{
          var r;
          if (typeof ajaxurl !== 'undefined') {
            r = await fetch(ajaxurl + '?action=patcherly_smart_connect', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' }
            });
          } else {
            // Non-WordPress fallback: unauthenticated health check only
            r = await fetch(serverUrl + '/api/health/summary');
          }
          if(!r.ok) throw new Error('HTTP '+r.status);
          var j = await r.json();

          if (j.success === false) {
            if (j.step === 'need_oauth') {
              setText(els.api, 'Not paired');
              setText(els.deploy, '—');
              setText(els.db, '—');
              setText(els.key, '—');
              setText(els.tenant, '—');
              setText(els.target, '—');
              setText(els.targetName, '');
              setText(els.meta, j.message || 'Use the Connect button to pair this site with Patcherly.');
              return;
            }
            throw new Error(j.message || 'Connection failed');
          }

          var data = j.data || j;
          setHTML(els.api, data.api_ok ? ('Reachable <span class="dashicons dashicons-yes"></span>')
                                       : ('Unavailable <span class="dashicons dashicons-no"></span>'));
          setText(els.deploy, data.deployment_type || '—');
          setText(els.db, (data.database_type || '').toUpperCase());

          // OAuth-connected status
          var oauthOk = data.oauth_connected !== false;
          setHTML(els.key, oauthOk
            ? 'OAuth active <span class="dashicons dashicons-yes"></span>'
            : 'Not paired <span class="dashicons dashicons-no"></span>');

          if (data.hmac_enabled != null) {
            setHTML(els.hmac, data.hmac_enabled
              ? 'Enabled <span class="dashicons dashicons-yes"></span>'
              : 'Disabled');
          } else {
            setText(els.hmac, '—');
          }

          var tName = data.tenant_name ? (data.tenant_name + ' (id ' + data.tenant_id + ')') : (data.tenant_id ? ('ID ' + data.tenant_id) : '—');
          setText(els.tenant, tName + (data.tenant_status ? (' — ' + data.tenant_status) : ''));
          setText(els.target, data.target_id != null ? ('ID ' + data.target_id) : '—');
          setText(els.targetName, data.target_name ? String(data.target_name) : '');

          // Cache IDs globally
          window.__PATCHERLY_TENANT_ID__ = (data.tenant_id != null ? String(data.tenant_id) : (window.__PATCHERLY_TENANT_ID__ || null));
          window.__PATCHERLY_TARGET_ID__ = (data.target_id != null ? String(data.target_id) : (window.__PATCHERLY_TARGET_ID__ || null));
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

          var successMsg = 'Connected successfully';
          if (j.step === 'connected' && j.message) successMsg = j.message;
          setText(els.meta, successMsg + ' at ' + (new Date()).toLocaleString());
        }catch(e){
          setText(els.api, 'Unavailable');
          setText(els.deploy, '—');
          setText(els.db, '—');
          setText(els.key, 'Unknown (check failed)');
          setText(els.tenant, '—');
          setText(els.target, '—');
          setText(els.targetName, '');
          var errorMsg = 'Check failed';
          if (e && e.message) {
            if (e.message.includes('503')) errorMsg = 'Service unavailable';
            else if (e.message.includes('502')) errorMsg = 'Bad gateway';
            else if (e.message.includes('504')) errorMsg = 'Gateway timeout';
            else if (e.message.includes('Failed to fetch') || e.message.includes('NetworkError')) errorMsg = 'Connection failed';
            else errorMsg = e.message;
          }
          setText(els.meta, 'Check failed at ' + (new Date()).toLocaleString() + ': ' + errorMsg);
        } finally { isRefreshing = false; }
      }

      if (els.btn){ els.btn.addEventListener('click', function(ev){ ev.preventDefault(); refresh(); }); }
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
