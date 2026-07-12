/*!
 * Debug page — copy captured entries as JSON or export as CSV (payload from wp_localize_script).
 */
(function () {
	function onReady(fn) {
		if (document.readyState === 'loading') {
			document.addEventListener('DOMContentLoaded', fn);
		} else {
			fn();
		}
	}

	function getPayload() {
		return (window.PATCHERLY_DEBUG && window.PATCHERLY_DEBUG.payload) || [];
	}

	function flashResult(out, message) {
		if (!out) {
			return;
		}
		out.textContent = message;
		setTimeout(function () {
			if (out) {
				out.textContent = '';
			}
		}, 1500);
	}

	function copyText(txt, out, okMsg, failMsg) {
		var done = function () {
			flashResult(out, okMsg);
		};
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(txt).then(done, function () {
				flashResult(out, failMsg);
			});
			return;
		}
		var ta = document.createElement('textarea');
		ta.value = txt;
		document.body.appendChild(ta);
		ta.select();
		try {
			document.execCommand('copy');
			done();
		} catch (e) {
			flashResult(out, failMsg);
		}
		document.body.removeChild(ta);
	}

	function csvCell(val) {
		var s = val == null ? '' : String(val);
		if (/[",\r\n]/.test(s)) {
			return '"' + s.replace(/"/g, '""') + '"';
		}
		return s;
	}

	function formatWhen(ts) {
		var n = parseInt(ts, 10);
		if (!n || isNaN(n)) {
			return '';
		}
		var d = new Date(n * 1000);
		if (isNaN(d.getTime())) {
			return '';
		}
		return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
	}

	function buildCsv(rows) {
		var header = ['When', 'Purpose', 'Method', 'URL', 'HTTP', 'Duration', 'Response'];
		var lines = [header.map(csvCell).join(',')];
		for (var i = 0; i < rows.length; i++) {
			var row = rows[i] || {};
			var ms = row.ms ? parseInt(row.ms, 10) : 0;
			lines.push([
				formatWhen(row.t),
				row.purpose || 'other',
				row.method || '-',
				row.url || '',
				row.code > 0 ? String(row.code) : '',
				ms > 0 ? ms + ' ms' : '',
				row.error || ''
			].map(csvCell).join(','));
		}
		return lines.join('\r\n');
	}

	function downloadCsv(csv) {
		var stamp = new Date().toISOString().slice(0, 10);
		var blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
		var url = URL.createObjectURL(blob);
		var a = document.createElement('a');
		a.href = url;
		a.download = 'patcherly-debug-' + stamp + '.csv';
		a.style.display = 'none';
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}

	onReady(function () {
		var out = document.getElementById('patcherly-debug-copy-result');
		var copyBtn = document.getElementById('patcherly-debug-copy-json');
		var csvBtn = document.getElementById('patcherly-debug-export-csv');

		if (copyBtn) {
			copyBtn.addEventListener('click', function () {
				var payload = getPayload();
				var txt = JSON.stringify(payload, null, 2);
				copyText(txt, out, 'Copied.', 'Copy failed — select the JSON below manually.');
			});
		}

		if (csvBtn) {
			csvBtn.addEventListener('click', function () {
				var payload = getPayload();
				if (!payload.length) {
					flashResult(out, 'No entries to export.');
					return;
				}
				downloadCsv(buildCsv(payload));
				flashResult(out, 'CSV downloaded.');
			});
		}
	});
})();
