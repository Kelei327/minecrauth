// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

const { ref, computed, onMounted } = window.Vue;
import { store } from '../store.js';
import { navigate } from '../router.js';
import { api } from '../api.js';
import { GrassBlock } from '../components/GrassBlock.js';
import { addToast } from '../components/Toast.js';

export const LoginView = {
    name: 'LoginView',
    components: {
        GrassBlock
    },
    setup() {
        const mode = ref('login'); // 'login', 'register', or 'forgot'
        const email = ref('');
        const password = ref('');
        const inviteCode = ref('');
        const loading = ref(false);
        const showResend = ref(false);

        const totpRequired = ref(false);
        const totpToken = ref('');
        const totpCode = ref('');

        // Registration is offered only when the server allows it: either open
        // registration, or invite-based with a code already in hand.
        const canRegister = computed(() => {
            const cfg = store.config;
            if (!cfg) return false;
            if (!cfg.requireInvite) return true;
            return inviteCode.value.trim() !== '';
        });

        const handleLogin = async () => {
            if (!email.value || !password.value) {
                addToast('Please fill in all fields', 'danger');
                return;
            }
            loading.value = true;
            try {
                const res = await api.post('/web/api/login', {
                    email: email.value.trim(),
                    password: password.value
                });
                if (res && res.totpRequired) {
                    totpToken.value = res.totpToken;
                    totpRequired.value = true;
                    totpCode.value = '';
                    addToast('Enter the 6-digit code from your authenticator app.', 'success');
                } else {
                    store.setSession(res.user, res.csrfToken, !!res.impersonating);
                    addToast('Logged in successfully', 'success');
                    navigate('/players');
                }
            } catch (err) {
                console.error(err);
                if (err.code === 'EmailNotVerified') {
                    addToast('Please verify your email first — check your inbox.', 'warning');
                    showResend.value = true;
                } else {
                    addToast('Login failed: ' + err.message, 'danger');
                }
            } finally {
                loading.value = false;
            }
        };

        const handleVerifyTOTP = async () => {
            if (!totpCode.value) {
                addToast('Please enter the verification code', 'danger');
                return;
            }
            loading.value = true;
            try {
                const res = await api.post('/web/api/login-totp', {
                    totpToken: totpToken.value,
                    code: totpCode.value.trim()
                });
                store.setSession(res.user, res.csrfToken, !!res.impersonating);
                addToast('Logged in successfully', 'success');
                navigate('/players');
            } catch (err) {
                console.error(err);
                if (err.code === 'InvalidTOTP') {
                    addToast('Invalid authentication code.', 'danger');
                } else if (err.status === 401) {
                    addToast('Your login attempt expired, please sign in again.', 'danger');
                    totpRequired.value = false;
                    totpCode.value = '';
                    totpToken.value = '';
                } else {
                    addToast('Verification failed: ' + err.message, 'danger');
                }
            } finally {
                loading.value = false;
            }
        };

        const handleRegister = async () => {
            if (!email.value || !password.value) {
                addToast('Please fill in all fields', 'danger');
                return;
            }
            loading.value = true;
            try {
                const user = await api.post('/api/register', {
                    email: email.value.trim(),
                    password: password.value,
                    inviteCode: inviteCode.value.trim()
                });
                if (user && user.email_verified === false) {
                    addToast('Account created. Check your email to verify your address before you can sign in.', 'success');
                    mode.value = 'login';
                    password.value = '';
                } else {
                    // Registration succeeded; log the new account straight in.
                    const res = await api.post('/web/api/login', {
                        email: email.value.trim(),
                        password: password.value
                    });
                    store.setSession(res.user, res.csrfToken, !!res.impersonating);
                    addToast('Account created. Welcome!', 'success');
                    navigate('/players');
                }
            } catch (err) {
                console.error(err);
                if (err.code === 'Conflict') {
                    addToast('That email is already registered.', 'danger');
                } else if (err.code === 'InvalidInvite') {
                    addToast('Invite code is invalid, expired or already used.', 'danger');
                } else if (err.code === 'WeakPassword') {
                    addToast('Password is too short.', 'danger');
                } else {
                    addToast('Registration failed: ' + err.message, 'danger');
                }
            } finally {
                loading.value = false;
            }
        };

        const handleResendVerification = async () => {
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

        const handleForgot = async () => {
            if (!email.value) {
                addToast('Please enter your email address', 'danger');
                return;
            }
            loading.value = true;
            try {
                await api.post('/api/forgot-password', {
                    email: email.value.trim()
                });
            } catch (err) {
                console.error(err);
            } finally {
                loading.value = false;
                addToast('If that email exists, a reset link has been sent.', 'success');
                switchMode('login');
            }
        };

        const switchMode = (m) => {
            mode.value = m;
            totpRequired.value = false;
            totpCode.value = '';
            totpToken.value = '';
        };

        onMounted(() => {
            const params = new URLSearchParams(window.location.search);
            if (params.get('error') === 'oidc') {
                addToast('Single Sign-On (OIDC) authentication failed.', 'danger');
            }
            // An invite link lands here with ?invite=CODE; open registration with it filled in.
            const invite = params.get('invite');
            if (invite) {
                inviteCode.value = invite;
                mode.value = 'register';
            }
        });

        return {
            mode,
            email,
            password,
            inviteCode,
            loading,
            showResend,
            canRegister,
            store,
            handleLogin,
            handleRegister,
            handleResendVerification,
            handleForgot,
            switchMode,
            totpRequired,
            totpToken,
            totpCode,
            handleVerifyTOTP
        };
    },
    template: `
        <div class="flex items-center justify-center" style="min-height: calc(100vh - 120px); padding: var(--s4);">
            <div class="panel" style="max-width: 420px; width: 100%; padding: var(--s5);">
                <!-- Logo & Brand Header -->
                <div class="flex-col items-center gap-2 text-center mb-5">
                    <GrassBlock />
                    <h1 class="font-pixel gold-text" style="font-size: 18px; margin-top: var(--s2);">minecrauth</h1>
                    <span v-if="mode !== 'login'" class="font-mono text-muted" style="font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">
                        {{ mode === 'register' ? 'Create Account' : 'Forgot Password' }}
                    </span>
                    <span v-else-if="totpRequired" class="font-mono text-muted" style="font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">
                        Two-Factor Auth
                    </span>
                </div>

                <!-- Two-Factor Auth form -->
                <form v-if="mode === 'login' && totpRequired" @submit.prevent="handleVerifyTOTP">
                    <p class="muted-text text-center mb-4" style="font-size: 0.85rem;">
                        Enter the 6-digit code from your authenticator app to complete sign in.
                    </p>
                    <div class="form-group">
                        <label for="totpCode">Authentication Code</label>
                        <input 
                            id="totpCode" 
                            type="text" 
                            v-model="totpCode" 
                            class="input font-mono" 
                            placeholder="123456" 
                            required 
                            autofocus
                            pattern="[0-9]*"
                            inputmode="numeric"
                            maxlength="6"
                        />
                    </div>
                    <button type="submit" class="btn btn-primary font-mono w-full mt-3" :disabled="loading">
                        {{ loading ? 'Verifying...' : 'Verify' }}
                    </button>
                    <div class="mt-3 text-center">
                        <a href="#" class="nav-link" @click.prevent="totpRequired = false; totpCode = ''; totpToken = '';">Back to sign in</a>
                    </div>
                </form>

                <!-- Login form -->
                <form v-else-if="mode === 'login' && !totpRequired" @submit.prevent="handleLogin">
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input id="email" type="email" v-model="email" class="input" placeholder="alex@steve.com" required />
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input id="password" type="password" v-model="password" class="input" placeholder="••••••••" required />
                    </div>
                    <button type="submit" class="btn btn-primary font-mono w-full mt-3" :disabled="loading">
                        {{ loading ? 'Signing in...' : 'Sign In' }}
                    </button>
                    <div v-if="showResend" class="mt-3 text-center">
                        <a href="#" class="nav-link" @click.prevent="handleResendVerification">Resend verification email</a>
                    </div>
                </form>

                <!-- Register form -->
                <form v-else-if="mode === 'register'" @submit.prevent="handleRegister">
                    <div class="form-group">
                        <label for="regEmail">Email Address</label>
                        <input id="regEmail" type="email" v-model="email" class="input" placeholder="alex@steve.com" required />
                    </div>
                    <div class="form-group">
                        <label for="regPassword">Password</label>
                        <input id="regPassword" type="password" v-model="password" class="input" placeholder="••••••••" required />
                    </div>
                    <div class="form-group" v-if="store.config && store.config.requireInvite">
                        <label for="regInvite">Invite Code</label>
                        <input id="regInvite" type="text" v-model="inviteCode" class="input font-mono" placeholder="Required to register" />
                    </div>
                    <button type="submit" class="btn btn-primary font-mono w-full mt-3" :disabled="loading || !canRegister">
                        {{ loading ? 'Creating...' : 'Create Account' }}
                    </button>
                    <p v-if="store.config && store.config.requireInvite && !canRegister" class="muted-text" style="font-size: 0.75rem; margin-top: var(--s2); text-align: center;">
                        Registration on this server requires an invite code.
                    </p>
                </form>

                <!-- Forgot form -->
                <form v-else-if="mode === 'forgot'" @submit.prevent="handleForgot">
                    <div class="form-group">
                        <label for="forgotEmail">Email Address</label>
                        <input id="forgotEmail" type="email" v-model="email" class="input" placeholder="alex@steve.com" required />
                    </div>
                    <button type="submit" class="btn btn-primary font-mono w-full mt-3" :disabled="loading">
                        {{ loading ? 'Sending...' : 'Send reset link' }}
                    </button>
                </form>

                <!-- Mode toggle -->
                <div v-if="!totpRequired" class="mt-4 text-center">
                    <a v-if="mode === 'login'" href="#" class="nav-link" @click.prevent="switchMode('register')">Need an account? Register</a>
                    <a v-else-if="mode === 'register'" href="#" class="nav-link" @click.prevent="switchMode('login')">Already have an account? Sign in</a>
                    <div v-if="mode === 'login' && store.config && store.config.smtpEnabled" class="mt-2">
                        <a href="#" class="nav-link" @click.prevent="switchMode('forgot')">Forgot password?</a>
                    </div>
                    <div v-if="mode === 'forgot'" class="mt-2">
                        <a href="#" class="nav-link" @click.prevent="switchMode('login')">Back to Login</a>
                    </div>
                </div>

                <!-- OIDC Login -->
                <div v-if="mode === 'login' && !totpRequired && store.config && store.config.oidcEnabled" class="mt-4" style="border-top: 2px dashed var(--border); padding-top: var(--s4);">
                    <a href="/oauth/login" class="btn font-mono w-full" style="background-color: var(--dirt); --bevel-light: var(--grass-bright); --bevel-dark: var(--dirt-dark); color: #fff;">
                        Sign in with Single Sign-On
                    </a>
                </div>
            </div>
        </div>
    `
};

export default LoginView;