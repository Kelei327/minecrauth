// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

const { reactive } = window.Vue;

export const store = reactive({
    currentUser: null,
    csrfToken: null,
    impersonating: false,
    config: null,
    initialized: false,

    async bootstrap() {
        try {
            // Fetch configuration flags first
            const configRes = await fetch('/web/api/config');
            if (configRes.ok) {
                this.config = await configRes.json();
            }
        } catch (e) {
            console.error("Failed to fetch web config", e);
        }

        try {
            // Fetch session info
            const sessionRes = await fetch('/web/api/session');
            if (sessionRes.ok) {
                const data = await sessionRes.json();
                this.currentUser = data.user;
                this.csrfToken = data.csrfToken;
                this.impersonating = !!data.impersonating;
            } else {
                this.currentUser = null;
                this.csrfToken = null;
                this.impersonating = false;
            }
        } catch (e) {
            console.warn("No active session or session fetch failed", e);
            this.currentUser = null;
            this.csrfToken = null;
            this.impersonating = false;
        }

        this.initialized = true;
    },

    setSession(user, csrfToken, impersonating = false) {
        this.currentUser = user;
        this.csrfToken = csrfToken;
        this.impersonating = impersonating;
    },

    clearSession() {
        this.currentUser = null;
        this.csrfToken = null;
        this.impersonating = false;
    }
});
