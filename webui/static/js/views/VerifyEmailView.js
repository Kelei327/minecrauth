// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

const { ref, onMounted } = window.Vue;
import { navigate } from '../router.js';
import { api } from '../api.js';
import { GrassBlock } from '../components/GrassBlock.js';
import { addToast } from '../components/Toast.js';

export const VerifyEmailView = {
    name: 'VerifyEmailView',
    components: {
        GrassBlock
    },
    setup() {
        const token = ref('');
        const status = ref('verifying'); // 'verifying' | 'success' | 'error'
        const email = ref('');
        const loading = ref(false);

        onMounted(async () => {
            const params = new URLSearchParams(window.location.search);
            const tok = params.get('token');
            if (!tok) {
                status.value = 'error';
            } else {
                token.value = tok;
                try {
                    await api.post('/api/verify-email', { token: tok });
                    status.value = 'success';
                    addToast('Email verified successfully! You can now sign in.', 'success');
                } catch (err) {
                    console.error(err);
                    status.value = 'error';
                }
            }
        });

        const handleResend = async () => {
            if (!email.value) {
                addToast('Please enter your email address', 'danger');
                return;
            }
            loading.value = true;
            try {
                await api.post('/api/resend-verification', {
                    email: email.value.trim()
                });
            } catch (err) {
                console.error(err);
            } finally {
                loading.value = false;
                addToast('If that account exists and is unverified, a new verification email has been sent.', 'success');
            }
        };

        return {
            status,
            email,
            loading,
            navigate,
            handleResend
        };
    },
    template: `
        <div class="flex items-center justify-center" style="min-height: calc(100vh - 120px); padding: var(--s4);">
            <div class="panel" style="max-width: 420px; width: 100%; padding: var(--s5);">
                <!-- Logo & Brand Header -->
                <div class="flex-col items-center gap-2 text-center mb-5">
                    <GrassBlock />
                    <h1 class="font-pixel gold-text" style="font-size: 18px; margin-top: var(--s2);">Verify Email</h1>
                    <span class="font-mono text-muted" style="font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">
                        Account Activation
                    </span>
                </div>

                <!-- Status: Verifying -->
                <div v-if="status === 'verifying'" class="text-center">
                    <p class="muted-text mb-4">Verifying your email...</p>
                    <div style="width: 32px; height: 32px; border: 4px solid var(--border); border-top-color: var(--grass); margin: 0 auto; animation: spin 1s linear infinite;"></div>
                </div>

                <!-- Status: Success -->
                <div v-else-if="status === 'success'" class="text-center">
                    <p class="muted-text mb-4">Your email address has been successfully verified!</p>
                    <button class="btn btn-primary font-mono w-full" @click="navigate('/login')">Continue to sign in</button>
                </div>

                <!-- Status: Error -->
                <div v-else class="text-center">
                    <p class="muted-text mb-4">This verification link is invalid or has expired.</p>
                    <form @submit.prevent="handleResend" class="text-left">
                        <div class="form-group">
                            <label for="resendEmail">Email Address</label>
                            <input id="resendEmail" type="email" v-model="email" class="input" placeholder="alex@steve.com" required />
                        </div>
                        <button type="submit" class="btn btn-primary font-mono w-full mt-3" :disabled="loading">
                            {{ loading ? 'Sending...' : 'Resend verification email' }}
                        </button>
                    </form>
                    <div class="mt-4 text-center">
                        <a href="#" class="nav-link" @click.prevent="navigate('/login')">Back to Login</a>
                    </div>
                </div>
            </div>
        </div>
    `
};

export default VerifyEmailView;