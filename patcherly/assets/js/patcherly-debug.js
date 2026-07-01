/*!
 * Debug page — copy captured entries as JSON (payload from wp_localize_script).
 */
(function () {
	function onReady(fn) {
		if (document.readyState === 'loading') {
			document.addEventListener('DOMContentLoaded', fn);
		} else {
			fn();
		}
	}

	onReady(function () {
		var btn = document.getElementById('patcherly-debug-copy-json');
		var out = document.getElementById('patcherly-debug-copy-result');
		if (!btn) {
			return;
		}
		btn.addEventListener('click', function () {
			var payload = window.PATCHERLY_DEBUG && window.PATCHERLY_DEBUG.payload;
			var txt = payload ? JSON.stringify(payload, null, 2) : '[]';
			var done = function () {
				if (out) {
					out.textContent = 'Copied.';
					setTimeout(function () {
						if (out) {
							out.textContent = '';
						}
					}, 1500);
				}
			};
			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(txt).then(done, function () {
					if (out) {
						out.textContent = 'Copy failed — select the JSON below manually.';
					}
				});
			} else {
				var ta = document.createElement('textarea');
				ta.value = txt;
				document.body.appendChild(ta);
				ta.select();
				try {
					document.execCommand('copy');
					done();
				} catch (e) {
					if (out) {
						out.textContent = 'Copy failed.';
					}
				}
				document.body.removeChild(ta);
			}
		});
	});
})();
