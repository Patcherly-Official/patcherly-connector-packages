(function(){
  var cfg = window.PATCHERLY_ERRORS || { url: '', key: '', ttl: 60, defaultLimit: 20 };
  function $(id){ return document.getElementById(id); }
  function setText(el, t){ if(el) el.textContent = t; }
  function headerObj(){ var h={}; if (cfg.key) h['X-API-Key']=cfg.key; return h; }
  function esc(s){ if(s==null) return ''; return (''+s).replace(/[&<>]/g, function(c){return ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]);}); }
  function fmtDate(s){ try{ var d=new Date(s); if(!isNaN(d)) return d.toLocaleString(); }catch(_){ } return s; }

  function initStatus(){ if (window.PatcherlyStatus) window.PatcherlyStatus.init('patcherly-errs', cfg.url, cfg.key); }

  async function loadErrors(force){
    var msg = $('patcherly-list-msg'); var tbody = $('patcherly-errors-tbody');
    if(!cfg.url){ setText(msg,'Missing Patcherly URL'); return; }
    if(!cfg.key){ setText(msg,'Missing Agent API Key'); }
    setText(msg,'Loading…');
    try{
      var p = new URLSearchParams();
      var s = ($('patcherly-flt-status') && $('patcherly-flt-status').value) || '';
      var sev = ($('patcherly-flt-sev') && $('patcherly-flt-sev').value) || '';
      var lang = ($('patcherly-flt-lang') && $('patcherly-flt-lang').value) || '';
      var lim = ($('patcherly-flt-limit') && $('patcherly-flt-limit').value) || String(cfg.defaultLimit||'50');
      if (s) p.set('status', s); if (sev) p.set('severity', sev); if (lang) p.set('language', lang); if (lim) p.set('limit', lim);
      var ttlToUse = force ? 0 : (parseInt(cfg.ttl,10)||0); if (ttlToUse > 0) p.set('ttl', String(ttlToUse)); else p.set('ttl','0');
      var r = await fetch((typeof ajaxurl!=='undefined'?ajaxurl:'') + '?action=patcherly_errors_list' + (p.toString()?('&'+p.toString()):''), { headers: { 'X-APR-Proxy': '1' } });
      if(!r.ok) throw new Error('HTTP '+r.status);
      var items = await r.json();
      tbody.innerHTML='';
      if (!Array.isArray(items) || !items.length){ tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#666">No data</td></tr>'; setText(msg,'Loaded 0'); return; }
      for (var i=0;i<items.length;i++){
        var it = items[i];
        var tr = document.createElement('tr');
        tr.setAttribute('data-id', it.id || '');
        var actions = '<button class="button-link patcherly-del-one">Delete</button>';
        if (it.status === 'awaiting_approval') {
          actions += ' <button class="button-link patcherly-approve-one">Approve</button>';
          actions += ' <button class="button-link patcherly-dismiss-one">Dismiss</button>';
        }
        tr.innerHTML = '<td style="width:28px"><input type="checkbox" class="patcherly-row-cb" /></td>'+
                       '<td>'+esc(fmtDate(it.created_at))+'</td>'+
                       '<td>'+esc(it.severity||'')+'</td>'+
                       '<td>'+esc(it.status||'')+'</td>'+
                       '<td>'+esc(it.language||'')+'</td>'+
                       '<td style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:540px" title="'+esc(it.log_line||'')+'">'+esc(it.log_line||'')+'</td>'+
                       '<td style="width:160px">'+actions+'</td>';
        tbody.appendChild(tr);
      }
      setText(msg,'Loaded '+items.length);
    }catch(e){
      setText(msg,'Failed: '+(e&&e.message?e.message:'error'));
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#666">No data</td></tr>';

      // Provide more specific error messages for API unavailability
      if (e && e.message) {
        if (e.message.includes('503')) {
          setText(msg, 'API server unavailable - please try again later');
        } else if (e.message.includes('502')) {
          setText(msg, 'API gateway error - please try again later');
        } else if (e.message.includes('504')) {
          setText(msg, 'API server timeout - please try again later');
        } else if (e.message.includes('Failed to fetch') || e.message.includes('NetworkError')) {
          setText(msg, 'Connection failed - please check your network connection');
        }
      }
    }
  }

  function bind(){
    var btn = $('patcherly-btn-refresh'); if (btn) btn.addEventListener('click', function(e){ e.preventDefault(); setText($('patcherly-list-msg'),'Refreshing…'); fetch((typeof ajaxurl!=='undefined'?ajaxurl:'') + '?action=patcherly_flush_errors_cache', { method:'POST' }).finally(function(){ loadErrors(true); }); });

    var fltLimit = $('patcherly-flt-limit');
    if (fltLimit) {
      var allowed = ['20','50','100'];
      var initial = String((cfg && cfg.defaultLimit) ? cfg.defaultLimit : '20');
      if (allowed.indexOf(initial) === -1) initial = '20';
      fltLimit.value = initial;
      fltLimit.addEventListener('change', function(){
        try{
          var fd = new FormData();
          fd.set('action','patcherly_save_default_limit');
          fd.set('value', this.value);
          fetch((typeof ajaxurl!=='undefined'?ajaxurl:''), { method:'POST', body: fd });
        }catch(_){ }
        loadErrors(false);
      });
    }

    // Row delete
    var tbody = $('patcherly-errors-tbody');
    if (tbody) tbody.addEventListener('click', async function(e){
      var t = e.target;
      if (t && t.classList && t.classList.contains('patcherly-del-one')){
        e.preventDefault();
        var tr = t.closest('tr');
        var id = tr && tr.getAttribute('data-id');
        if (!id) return;
        try{
          var r = await fetch((cfg.url||'') + '/api/errors/' + encodeURIComponent(id), { method:'DELETE', headers: headerObj() });
          if (r.ok){
            tr.remove();
          }
        }catch(_){ }
      } else if (t && t.classList && t.classList.contains('patcherly-approve-one')){
        e.preventDefault();
        var trA = t.closest('tr');
        var idA = trA && trA.getAttribute('data-id');
        if (!idA) return;
        try{
          var rA = await fetch((cfg.url||'') + '/api/errors/' + encodeURIComponent(idA) + '/approve', { method:'POST', headers: headerObj() });
          if (rA.ok){ loadErrors(true); }
        }catch(_){ }
      } else if (t && t.classList && t.classList.contains('patcherly-dismiss-one')){
        e.preventDefault();
        var trD = t.closest('tr');
        var idD = trD && trD.getAttribute('data-id');
        if (!idD) return;
        try{
          var rD = await fetch((cfg.url||'') + '/api/errors/' + encodeURIComponent(idD) + '/dismiss', { method:'POST', headers: headerObj() });
          if (rD.ok){ loadErrors(true); }
        }catch(_){ }
      }
    });

    // Bulk select + delete
    var selAll = document.getElementById('patcherly-cb-all');
    if (selAll && tbody){
      selAll.addEventListener('change', function(){
        var cbs = tbody.querySelectorAll('.patcherly-row-cb');
        cbs.forEach(function(cb){ cb.checked = selAll.checked; });
      });
    }
    var bulkBtn = document.getElementById('patcherly-btn-del-selected');
    if (bulkBtn && tbody){
      bulkBtn.addEventListener('click', async function(e){
        e.preventDefault();
        var ids = Array.from(tbody.querySelectorAll('tr')).filter(function(tr){ var cb = tr.querySelector('.patcherly-row-cb'); return cb && cb.checked; }).map(function(tr){ return tr.getAttribute('data-id'); }).filter(Boolean);
        if (!ids.length) return;
        try{
          var r = await fetch((cfg.url||'') + '/api/errors/bulk-delete', { method:'POST', headers: Object.assign({'Content-Type':'application/json'}, headerObj()), body: JSON.stringify({ ids: ids }) });
          if (r.ok){
            // Remove deleted rows and refresh cache/list
            Array.from(tbody.querySelectorAll('tr')).forEach(function(tr){ if (ids.indexOf(tr.getAttribute('data-id'))!==-1) tr.remove(); });
            try { await fetch((typeof ajaxurl!=='undefined'?ajaxurl:'') + '?action=patcherly_flush_errors_cache', { method:'POST' }); } catch(_){ }
            loadErrors(true);
          }
        }catch(_){ }
      });
    }
  }

  if (document.readyState === 'complete') { initStatus(); bind(); loadErrors(false); }
  else { window.addEventListener('load', function(){ initStatus(); bind(); loadErrors(false); }); }
})();
