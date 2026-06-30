// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

const { ref, watch } = window.Vue;
import { store } from './store.js';

export const currentPath = ref(window.location.pathname);

export function navigate(path) {
    if (window.location.pathname !== path) {
        window.history.pushState(null, '', path);
        currentPath.value = path;
    }
}

// Global listen for browser back/forward buttons
window.addEventListener('popstate', () => {
    currentPath.value = window.location.pathname;
});

// Guard and redirect logic
export function routeGuard() {
    if (!store.initialized) return;

    const path = currentPath.value;

    if (!store.currentUser) {
        // Not logged in: only allow /login, /oauth-callback, /reset and /verify
        if (path !== '/login' && path !== '/oauth-callback' && path !== '/reset' && path !== '/verify') {
            navigate('/login');
        }
    } else {
        // Logged in:
        if (path === '/' || path === '/login' || path === '/oauth-callback') {
            navigate('/players');
        } else if (path === '/admin-ui' && !store.currentUser.is_admin) {
            navigate('/players');
        }
    }
}

// Watch for changes in store initialization or user state to re-evaluate route
watch(() => [store.initialized, store.currentUser, currentPath.value], () => {
    routeGuard();
}, { immediate: true });
