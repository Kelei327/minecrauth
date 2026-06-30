// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * minecrauth Vue SPA app.js
 * 
 * Main orchestration script for the Minecraft-crafted admin and player portal.
 * Highly modular, using native ES modules to maintain absolute clarity.
 */

const { createApp, computed, onMounted } = window.Vue;
import { store } from './store.js';
import { currentPath, navigate } from './router.js';

// Import Views
import { LoginView } from './views/LoginView.js';
import { AccountView } from './views/AccountView.js';
import { PlayersView } from './views/PlayersView.js';
import { AdminView } from './views/AdminView.js';
import { OAuthCallbackView } from './views/OAuthCallbackView.js';
import { ResetPasswordView } from './views/ResetPasswordView.js';
import { VerifyEmailView } from './views/VerifyEmailView.js';

// Import Global Components
import { AppHeader } from './components/AppHeader.js';
import { ImpersonationBanner } from './components/ImpersonationBanner.js';
import { ToastContainer } from './components/Toast.js';

const App = {
    name: 'MinecrauthApp',
    components: {
        AppHeader,
        ImpersonationBanner,
        ToastContainer
    },
    setup() {
        // Resolve current view component reactively
        const activeView = computed(() => {
            switch (currentPath.value) {
                case '/login':
                    return LoginView;
                case '/account':
                    return AccountView;
                case '/players':
                    return PlayersView;
                case '/admin-ui':
                    return AdminView;
                case '/oauth-callback':
                    return OAuthCallbackView;
                case '/reset':
                    return ResetPasswordView;
                case '/verify':
                    return VerifyEmailView;
                default:
                    // If not initialized, stay blank; once initialized routeGuard redirects
                    return null;
            }
        });

        onMounted(async () => {
            // Bootstrap shared session state and configurations
            await store.bootstrap();
        });

        return {
            store,
            activeView
        };
    },
    template: `
        <div class="flex-col min-h-screen" style="min-height: 100vh; display: flex; flex-direction: column;">
            <!-- Header (Logo + Brand + Nav + Logout) -->
            <AppHeader />

            <!-- Impersonation Banner (Visible to admins mimicking users) -->
            <ImpersonationBanner />

            <!-- Main Content viewport wrapper -->
            <main class="flex-grow w-full" style="flex: 1 0 auto;">
                <div v-if="!store.initialized" class="container text-center" style="margin-top: var(--s6);">
                    <div class="font-pixel gold-text" style="font-size: 14px; margin-bottom: var(--s3);">Loading minecrauth...</div>
                    <div style="width: 32px; height: 32px; border: 4px solid var(--border); border-top-color: var(--grass); margin: 0 auto; animation: spin 1s linear infinite;"></div>
                </div>
                
                <component v-else-if="activeView" :is="activeView" />
            </main>

            <!-- Global Toast notification containers -->
            <ToastContainer />
        </div>
    `
};

// Mount the Vue App
createApp(App).mount('#app');
