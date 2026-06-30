// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

import { store } from './store.js';
import { navigate } from './router.js';

export async function request(method, url, options = {}) {
    const headers = { ...options.headers };

    // Mark every SPA request as an XHR. The server uses this to suppress the
    // "WWW-Authenticate: Basic" challenge on 401 responses, which would otherwise
    // make the browser pop its native Basic-auth dialog instead of letting the
    // app redirect to the login view.
    headers['X-Requested-With'] = 'XMLHttpRequest';

    // Set JSON headers if body is a plain object/array
    let body = options.body;
    if (body && typeof body === 'object' && !(body instanceof FormData) && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
        body = JSON.stringify(body);
        headers['Content-Type'] = 'application/json';
    }

    // Set CSRF token on mutations
    const isMutation = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase());
    if (isMutation && store.csrfToken) {
        headers['X-CSRF-Token'] = store.csrfToken;
    }

    const res = await fetch(url, {
        method,
        headers,
        body,
        credentials: 'same-origin',
    });

    // Parse response
    let data = null;
    const contentType = res.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
        data = await res.json();
    } else {
        data = await res.text();
    }

    if (!res.ok) {
        // A 401 means the browser session is missing or expired. Clear local
        // state and send the user to the login view so they re-authenticate
        // through the app form. The login request itself is exempt: its 401
        // must surface as an inline "invalid credentials" error, not a redirect.
        if (res.status === 401 && !url.includes('/web/api/login')) {
            store.clearSession();
            navigate('/login');
        }
        const errorMsg = (data && typeof data === 'object' && data.message) 
            || (data && typeof data === 'object' && data.error)
            || (typeof data === 'string' && data)
            || `Request failed with status ${res.status}`;
        const err = new Error(errorMsg);
        err.status = res.status;
        // Preserve the backend error code (e.g. "PlayerLimitReached", "Conflict")
        // so callers can show a specific message instead of a generic one.
        err.code = (data && typeof data === 'object' && data.error) || '';
        throw err;
    }

    return data;
}

export const api = {
    get: (url, options) => request('GET', url, options),
    post: (url, body, options) => request('POST', url, { ...options, body }),
    put: (url, body, options) => request('PUT', url, { ...options, body }),
    patch: (url, body, options) => request('PATCH', url, { ...options, body }),
    delete: (url, options) => request('DELETE', url, options),
};
