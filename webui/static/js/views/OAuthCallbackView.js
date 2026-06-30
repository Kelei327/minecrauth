// SPDX-License-Identifier: Apache-2.0

const { onMounted } = window.Vue;
import { store } from '../store.js';
import { navigate } from '../router.js';
import { addToast } from '../components/Toast.js';

export const OAuthCallbackView = {
    name: 'OAuthCallbackView',
    setup() {
        onMounted(async () => {
            try {
                // Fetch the fresh session status to see if login succeeded
                await store.bootstrap();
                if (store.currentUser) {
                    addToast('Successfully authenticated via Single Sign-On!', 'success');
                    navigate('/players');
                } else {
                    addToast('Failed to start session. Please try logging in again.', 'danger');
                    navigate('/login');
                }
            } catch (err) {
                console.error(err);
                addToast('Authentication error: ' + err.message, 'danger');
                navigate('/login');
            }
        });

        return {};
    },
    template: `
        <div class="flex items-center justify-center" style="min-height: calc(100vh - 120px); padding: var(--s4);">
            <div class="panel text-center" style="max-width: 400px; width: 100%; padding: var(--s5);">
                <div class="eyebrow">SINGLE SIGN-ON</div>
                <h1 class="font-pixel gold-text" style="font-size: 14px; margin-top: var(--s2); margin-bottom: var(--s3);">Signing you in...</h1>
                <div class="font-mono text-muted" style="font-size: 0.85rem;">
                    Exchanging authorization token and establishing secure Minecraft session. Please wait.
                </div>
                <div style="margin-top: var(--s4);">
                    <!-- Minecraft styled pixel animated spinner placeholder -->
                    <div style="width: 24px; height: 24px; border: 4px solid var(--border); border-top-color: var(--grass); margin: 0 auto; animation: spin 1s linear infinite;"></div>
                </div>
            </div>
        </div>
        <style>
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    `
};

export default OAuthCallbackView;
