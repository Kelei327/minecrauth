// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

import { store } from '../store.js';
import { navigate } from '../router.js';
import { api } from '../api.js';
import { addToast } from './Toast.js';

export const ImpersonationBanner = {
    name: 'ImpersonationBanner',
    setup() {
        const handleStopImpersonation = async () => {
            try {
                await api.post('/web/api/stop-impersonation');
                await store.bootstrap();
                addToast('Returned to admin session', 'success');
                navigate('/admin-ui');
            } catch (err) {
                console.error(err);
                addToast('Failed to return to admin: ' + err.message, 'danger');
            }
        };

        return {
            store,
            handleStopImpersonation
        };
    },
    template: `
        <div v-if="store.impersonating" class="impersonation-banner">
            <div class="banner-text">
                <span class="banner-tag">IMPERSONATING</span> You are acting as {{ store.currentUser ? store.currentUser.email : 'another user' }}
            </div>
            <button class="btn btn-primary font-mono" style="padding: 4px 12px; font-size: 0.75rem;" @click="handleStopImpersonation">
                Return to Admin
            </button>
        </div>
    `
};

export default ImpersonationBanner;
