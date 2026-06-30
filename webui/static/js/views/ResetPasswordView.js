const { ref, onMounted } = window.Vue;
import { navigate } from '../router.js';
import { api } from '../api.js';
import { GrassBlock } from '../components/GrassBlock.js';
import { addToast } from '../components/Toast.js';

export const ResetPasswordView = {
    name: 'ResetPasswordView',
    components: {
        GrassBlock
    },
    setup() {
        const token = ref('');
        const password = ref('');
        const confirmPassword = ref('');
        const loading = ref(false);
        const hasToken = ref(true);

        onMounted(() => {
            const params = new URLSearchParams(window.location.search);
            const tok = params.get('token');
            if (!tok) {
                hasToken.value = false;
                addToast('Reset token is missing from the URL.', 'danger');
            } else {
                token.value = tok;
            }
        });

        const handleSubmit = async () => {
            if (!token.value) {
                addToast('Cannot reset password without a valid token.', 'danger');
                return;
            }
            if (!password.value || !confirmPassword.value) {
                addToast('Please fill in both password fields.', 'danger');
                return;
            }
            if (password.value !== confirmPassword.value) {
                addToast('Passwords do not match.', 'danger');
                return;
            }

            loading.value = true;
            try {
                await api.post('/api/reset-password', {
                    token: token.value,
                    password: password.value
                });
                addToast('Your password has been reset. Please sign in.', 'success');
                navigate('/login');
            } catch (err) {
                console.error(err);
                if (err.code === 'InvalidToken') {
                    addToast('This reset link is invalid or has expired.', 'danger');
                } else if (err.code === 'WeakPassword') {
                    addToast('Password is too short.', 'danger');
                } else {
                    addToast('Failed to reset password: ' + err.message, 'danger');
                }
            } finally {
                loading.value = false;
            }
        };

        return {
            token,
            password,
            confirmPassword,
            loading,
            hasToken,
            handleSubmit
        };
    },
    template: `
        <div class="flex items-center justify-center" style="min-height: calc(100vh - 120px); padding: var(--s4);">
            <div class="panel" style="max-width: 420px; width: 100%; padding: var(--s5);">
                <!-- Logo & Brand Header -->
                <div class="flex-col items-center gap-2 text-center mb-5">
                    <GrassBlock />
                    <h1 class="font-pixel gold-text" style="font-size: 18px; margin-top: var(--s2);">Reset Password</h1>
                    <span class="font-mono text-muted" style="font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;">
                        Password Recovery
                    </span>
                </div>

                <div v-if="!hasToken" class="text-center">
                    <p class="muted-text mb-4">No password reset token was provided. Please request a new reset link from your administrator.</p>
                    <button class="btn font-mono w-full" @click="navigate('/login')">Go to Login</button>
                </div>

                <!-- Reset Form -->
                <form v-else @submit.prevent="handleSubmit">
                    <div class="form-group">
                        <label for="newPassword">New Password</label>
                        <input id="newPassword" type="password" v-model="password" class="input" placeholder="••••••••" required />
                    </div>
                    <div class="form-group">
                        <label for="confirmPassword">Confirm New Password</label>
                        <input id="confirmPassword" type="password" v-model="confirmPassword" class="input" placeholder="••••••••" required />
                    </div>
                    <button type="submit" class="btn btn-primary font-mono w-full mt-3" :disabled="loading">
                        {{ loading ? 'Updating...' : 'Set New Password' }}
                    </button>
                </form>

                <div class="mt-4 text-center">
                    <a href="#" class="nav-link" @click.prevent="navigate('/login')">Back to Login</a>
                </div>
            </div>
        </div>
    `
};

export default ResetPasswordView;
