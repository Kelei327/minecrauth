const { ref, computed } = window.Vue;
import { store } from '../store.js';
import { navigate } from '../router.js';
import { api } from '../api.js';
import { addToast } from '../components/Toast.js';
import { ConfirmModal } from '../components/ConfirmModal.js';

export const AccountView = {
    name: 'AccountView',
    components: {
        ConfirmModal
    },
    setup() {
        const email = ref(store.currentUser ? store.currentUser.email : '');
        const newEmail = ref('');
        const password = ref('');
        const confirmPassword = ref('');

        const gamePassword = ref('');
        const showGamePassword = ref(false);

        // Single reusable confirmation modal, driven by reactive state. Every
        // sensitive action (change email, change password, delete account)
        // routes through it so nothing destructive happens on a single click.
        const showConfirm = ref(false);
        const confirmTitle = ref('');
        const confirmMsg = ref('');
        const confirmLabel = ref('Confirm');
        const confirmVariant = ref('primary');
        const confirmAction = ref(null);

        const openConfirm = (title, message, label, variant, action) => {
            confirmTitle.value = title;
            confirmMsg.value = message;
            confirmLabel.value = label;
            confirmVariant.value = variant;
            confirmAction.value = action;
            showConfirm.value = true;
        };

        const handleConfirm = () => {
            const action = confirmAction.value;
            showConfirm.value = false;
            confirmAction.value = null;
            if (action) {
                action();
            }
        };

        // --- Change email ---
        const executeChangeEmail = async () => {
            try {
                await api.put('/api/me/email', { email: newEmail.value.trim() });
                addToast('Email updated successfully. Please use your new email to sign in next time.', 'success');
                if (store.currentUser) {
                    store.currentUser.email = newEmail.value.trim();
                }
                email.value = newEmail.value.trim();
                newEmail.value = '';
            } catch (err) {
                console.error(err);
                addToast('Failed to change email: ' + err.message, 'danger');
            }
        };

        const handleChangeEmail = () => {
            if (!newEmail.value || newEmail.value.trim() === '') {
                addToast('Email address cannot be empty', 'danger');
                return;
            }
            openConfirm(
                'Change Email Address',
                `Change your account email to "${newEmail.value.trim()}"? You will need to sign in with the new address from now on.`,
                'Change Email',
                'primary',
                executeChangeEmail
            );
        };

        // --- Change password ---
        const executeChangePassword = async () => {
            try {
                await api.put('/api/me/password', { password: password.value });
                addToast('Password changed successfully', 'success');
                password.value = '';
                confirmPassword.value = '';
            } catch (err) {
                console.error(err);
                addToast('Failed to change password: ' + err.message, 'danger');
            }
        };

        const handleChangePassword = () => {
            if (!password.value) {
                addToast('Password cannot be empty', 'danger');
                return;
            }
            if (password.value !== confirmPassword.value) {
                addToast('Passwords do not match', 'danger');
                return;
            }
            openConfirm(
                'Change Password',
                'Change your account password? Any other active sessions will keep working until they expire, but you will use the new password next time you sign in.',
                'Change Password',
                'primary',
                executeChangePassword
            );
        };

        // --- Game password ---
        // Generate a strong random game password and reveal it so the user can copy it
        // into their launcher. It is still stored hashed; this only fills the field.
        const generateGamePassword = () => {
            const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
            const bytes = new Uint32Array(16);
            (window.crypto || {}).getRandomValues
                ? window.crypto.getRandomValues(bytes)
                : bytes.forEach((_, i) => (bytes[i] = Math.floor(Math.random() * 1e9)));
            let out = '';
            for (let i = 0; i < 16; i++) out += chars[bytes[i] % chars.length];
            gamePassword.value = out;
            showGamePassword.value = true;
        };

        const executeSetGamePassword = async () => {
            try {
                await api.put('/api/me/game-password', { password: gamePassword.value.trim() });
                addToast('Game password updated successfully', 'success');
                gamePassword.value = '';
                showGamePassword.value = false;
                if (store.currentUser) {
                    store.currentUser.game_password_set = true;
                }
            } catch (err) {
                console.error(err);
                if (err.code === 'WeakPassword') {
                    addToast('Game password is too short.', 'danger');
                } else {
                    addToast('Failed to set game password: ' + err.message, 'danger');
                }
            }
        };

        const handleSetGamePassword = () => {
            if (!gamePassword.value || gamePassword.value.trim() === '') {
                addToast('Game password cannot be empty', 'danger');
                return;
            }
            openConfirm(
                'Set game password',
                'This sets the password you type into the Minecraft launcher. After this, your normal account password will not work in the launcher anymore, and anyone currently playing with this account gets disconnected. Continue?',
                'Set password',
                'primary',
                executeSetGamePassword
            );
        };

        const executeClearGamePassword = async () => {
            try {
                await api.delete('/api/me/game-password');
                addToast('Game password cleared successfully', 'success');
                if (store.currentUser) {
                    store.currentUser.game_password_set = false;
                }
            } catch (err) {
                console.error(err);
                addToast('Failed to clear game password: ' + err.message, 'danger');
            }
        };

        const handleClearGamePassword = () => {
            openConfirm(
                'Remove game password',
                'Remove the game password? The launcher will go back to using your normal account password, and anyone currently playing gets disconnected. Continue?',
                'Remove',
                'danger',
                executeClearGamePassword
            );
        };

        // --- Delete account ---
        const executeDeleteAccount = async () => {
            try {
                await api.delete('/api/me');
                try {
                    await api.post('/web/api/logout');
                } catch (e) {}
                store.clearSession();
                addToast('Your account was deleted successfully', 'success');
                navigate('/login');
            } catch (err) {
                console.error(err);
                addToast('Failed to delete account: ' + err.message, 'danger');
            }
        };

        const handleDeleteAccount = () => {
            openConfirm(
                'Delete Your Account',
                'Are you absolutely sure you want to delete your account? All players, skins, capes, and metadata will be permanently erased. This action is irreversible.',
                'Delete Permanently',
                'danger',
                executeDeleteAccount
            );
        };

        // --- Two-Factor Authentication (2FA) ---
        const totpSetup = ref(null);
        const recoveryCodes = ref([]);
        const totpCode = ref('');
        const disableCode = ref('');
        const showDisablePrompt = ref(false);

        const startTOTPSetup = async () => {
            try {
                const res = await api.post('/api/me/totp/setup');
                totpSetup.value = res;
                totpCode.value = '';
            } catch (err) {
                console.error(err);
                addToast('Failed to start TOTP setup: ' + err.message, 'danger');
            }
        };

        const confirmTOTP = async () => {
            if (!totpCode.value || totpCode.value.trim() === '') {
                addToast('Please enter the 6-digit code', 'danger');
                return;
            }
            try {
                const res = await api.post('/api/me/totp/confirm', { code: totpCode.value.trim() });
                recoveryCodes.value = res.recoveryCodes || [];
                if (store.currentUser) {
                    store.currentUser.totp_enabled = true;
                }
                totpSetup.value = null;
                totpCode.value = '';
                addToast('2FA enabled successfully', 'success');
            } catch (err) {
                console.error(err);
                if (err.code === 'InvalidTOTP') {
                    addToast('That code is not valid. Try again.', 'danger');
                } else {
                    addToast('Failed to confirm 2FA: ' + err.message, 'danger');
                }
            }
        };

        const copySecret = async () => {
            if (totpSetup.value && totpSetup.value.secret) {
                try {
                    await navigator.clipboard.writeText(totpSetup.value.secret);
                    addToast('Secret copied to clipboard', 'success');
                } catch (err) {
                    addToast('Failed to copy secret: ' + err.message, 'danger');
                }
            }
        };

        const copyRecoveryCodes = async () => {
            if (recoveryCodes.value && recoveryCodes.value.length > 0) {
                try {
                    await navigator.clipboard.writeText(recoveryCodes.value.join('\n'));
                    addToast('Recovery codes copied to clipboard', 'success');
                } catch (err) {
                    addToast('Failed to copy recovery codes: ' + err.message, 'danger');
                }
            }
        };

        const finishRecovery = () => {
            recoveryCodes.value = [];
        };

        const triggerDisable = () => {
            showDisablePrompt.value = true;
        };

        const disableTOTP = async () => {
            if (!disableCode.value || disableCode.value.trim() === '') {
                addToast('Please enter a verification or recovery code', 'danger');
                return;
            }
            try {
                await api.post('/api/me/totp/disable', { code: disableCode.value.trim() });
                if (store.currentUser) {
                    store.currentUser.totp_enabled = false;
                }
                showDisablePrompt.value = false;
                disableCode.value = '';
                addToast('2FA disabled successfully', 'success');
            } catch (err) {
                console.error(err);
                if (err.code === 'InvalidTOTP') {
                    addToast('That code is not valid.', 'danger');
                } else {
                    addToast('Failed to disable 2FA: ' + err.message, 'danger');
                }
            }
        };

        return {
            store,
            email,
            newEmail,
            password,
            confirmPassword,
            gamePassword,
            showGamePassword,
            generateGamePassword,
            showConfirm,
            confirmTitle,
            confirmMsg,
            confirmLabel,
            confirmVariant,
            handleConfirm,
            handleChangeEmail,
            handleChangePassword,
            handleSetGamePassword,
            handleClearGamePassword,
            handleDeleteAccount,
            totpSetup,
            recoveryCodes,
            totpCode,
            disableCode,
            showDisablePrompt,
            startTOTPSetup,
            confirmTOTP,
            copySecret,
            copyRecoveryCodes,
            finishRecovery,
            triggerDisable,
            disableTOTP
        };
    },
    template: `
        <div class="container" style="max-width: 650px;">
            <div class="mb-4">
                <span class="eyebrow">SETTINGS</span>
                <h1 class="font-pixel" style="font-size: 18px; margin-top: var(--s1); margin-bottom: var(--s1);">Account Settings</h1>
                <p class="muted-text">Manage your credentials, login settings, and account data.</p>
            </div>

            <!-- Current Account Status -->
            <div class="panel">
                <div class="eyebrow">ACCOUNT EMAIL</div>
                <div class="font-mono mt-1" style="font-size: 1rem; font-weight: bold; color: var(--gold);">
                    {{ email }}
                </div>
            </div>

            <!-- Change Email -->
            <div class="panel">
                <div class="eyebrow">CHANGE EMAIL</div>
                <form @submit.prevent="handleChangeEmail" class="mt-3">
                    <div class="form-group">
                        <label for="newEmail">New Email Address</label>
                        <input 
                            id="newEmail"
                            type="email" 
                            v-model="newEmail" 
                            class="input"
                            placeholder="new-email@example.com"
                            required
                        />
                    </div>
                    <button type="submit" class="btn btn-primary font-mono mt-2">
                        Update Email
                    </button>
                </form>
            </div>

            <!-- Change Password -->
            <div class="panel">
                <div class="eyebrow">CHANGE PASSWORD</div>
                <form @submit.prevent="handleChangePassword" class="mt-3">
                    <div class="form-group">
                        <label for="pwd">New Password</label>
                        <input 
                            id="pwd"
                            type="password" 
                            v-model="password" 
                            class="input"
                            placeholder="••••••••"
                            required
                        />
                    </div>
                    <div class="form-group">
                        <label for="confirmPwd">Confirm New Password</label>
                        <input 
                            id="confirmPwd"
                            type="password" 
                            v-model="confirmPassword" 
                            class="input"
                            placeholder="••••••••"
                            required
                        />
                    </div>
                    <button type="submit" class="btn btn-primary font-mono mt-2">
                        Update Password
                    </button>
                </form>
            </div>

            <!-- Game Password -->
            <div class="panel">
                <div class="eyebrow">GAME PASSWORD</div>

                <p class="muted-text" style="font-size: 0.85rem; margin-top: var(--s2); margin-bottom: var(--s2);">
                    The password you type into the Minecraft launcher to play, separate from your
                    website password. Changing or removing it kicks you out of any current game.
                </p>

                <div class="mb-3 flex items-center gap-2">
                    <template v-if="store.currentUser && store.currentUser.game_password_set">
                        <span class="badge badge-active">SET</span>
                    </template>
                    <template v-else>
                        <span class="badge badge-blocked">NOT SET</span>
                    </template>
                </div>

                <form @submit.prevent="handleSetGamePassword" class="mt-3">
                    <div class="form-group">
                        <label for="gamePwd">{{ store.currentUser && store.currentUser.game_password_set ? 'New game password' : 'Game password' }}</label>
                        <div class="flex gap-2" style="align-items: stretch;">
                            <input 
                                id="gamePwd"
                                :type="showGamePassword ? 'text' : 'password'" 
                                v-model="gamePassword" 
                                class="input font-mono"
                                style="flex: 1;"
                                placeholder="Type one or hit Generate"
                                required
                            />
                            <button type="button" class="btn font-mono" style="flex-shrink: 0;" @click="showGamePassword = !showGamePassword">
                                {{ showGamePassword ? 'Hide' : 'Show' }}
                            </button>
                            <button type="button" class="btn font-mono" style="flex-shrink: 0;" @click="generateGamePassword">
                                Generate
                            </button>
                        </div>
                    </div>
                    <div class="flex gap-2">
                        <button type="submit" class="btn btn-primary font-mono">
                            {{ store.currentUser && store.currentUser.game_password_set ? 'Change game password' : 'Set game password' }}
                        </button>
                        <button 
                            v-if="store.currentUser && store.currentUser.game_password_set"
                            type="button" 
                            class="btn btn-danger font-mono"
                            @click="handleClearGamePassword"
                        >
                            Remove
                        </button>
                    </div>
                </form>
            </div>

            <!-- Two-Factor Authentication (2FA) -->
            <div class="panel">
                <div class="eyebrow">TWO-FACTOR AUTHENTICATION</div>

                <!-- State C: Recovery Codes (shown once after confirm) -->
                <div v-if="recoveryCodes && recoveryCodes.length > 0" class="mt-3">
                    <p class="muted-text" style="font-size: 0.85rem; margin-bottom: var(--s2);">
                        Each code works once. Store them somewhere safe — they let you sign in if you lose your authenticator.
                    </p>
                    <div class="panel-2 p-3 font-mono mb-3" style="border: 2px dashed var(--border); background: var(--dark-bg); max-height: 200px; overflow-y: auto;">
                        <div v-for="code in recoveryCodes" :key="code" style="padding: var(--s1) 0; color: var(--gold);">
                            {{ code }}
                        </div>
                    </div>
                    <div class="flex gap-2">
                        <button type="button" class="btn font-mono" @click="copyRecoveryCodes">
                            Copy all
                        </button>
                        <button type="button" class="btn btn-primary font-mono" @click="finishRecovery">
                            Done
                        </button>
                    </div>
                </div>

                <!-- State B: Setting Up -->
                <div v-else-if="totpSetup" class="mt-3">
                    <p class="muted-text" style="font-size: 0.85rem; margin-bottom: var(--s3);">
                        Scan this with your authenticator app (such as Google Authenticator, Authy, or 1Password).
                    </p>
                    <div style="width: fit-content; margin: 0 auto var(--s5); padding: var(--s3); border: 2px solid var(--border); background: rgba(0,0,0,0.2);">
                        <img :src="totpSetup.qrPng" alt="TOTP QR Code" style="width: 200px; height: 200px; display: block;" />
                    </div>
                    <div class="form-group">
                        <label>Can't scan? Enter this code manually:</label>
                        <div class="flex gap-2" style="align-items: stretch;">
                            <span class="input font-mono flex items-center" style="flex: 1; overflow-x: auto; white-space: nowrap; font-size: 0.9rem; background: var(--dark-bg);">
                                {{ totpSetup.secret }}
                            </span>
                            <button type="button" class="btn font-mono" style="flex-shrink: 0;" @click="copySecret">
                                Copy
                            </button>
                        </div>
                    </div>
                    <form @submit.prevent="confirmTOTP" class="mt-3">
                        <div class="form-group">
                            <label for="totpCode">Verification Code</label>
                            <input 
                                id="totpCode"
                                type="text" 
                                v-model="totpCode" 
                                class="input font-mono"
                                placeholder="123456"
                                required
                                pattern="[0-9]*"
                                inputmode="numeric"
                                maxlength="6"
                            />
                        </div>
                        <div class="flex gap-2">
                            <button type="submit" class="btn btn-primary font-mono">
                                Verify & Enable
                            </button>
                            <button type="button" class="btn font-mono" @click="totpSetup = null">
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>

                <!-- State D: Enabled -->
                <div v-else-if="store.currentUser && store.currentUser.totp_enabled" class="mt-3">
                    <div class="mb-3 flex items-center gap-2">
                        <span class="badge badge-active">ENABLED</span>
                    </div>
                    <p class="muted-text" style="font-size: 0.85rem; margin-bottom: var(--s3);">
                        Protects your website login with a 6-digit code from your authenticator app.
                    </p>
                    
                    <div v-if="showDisablePrompt" class="mt-3">
                        <form @submit.prevent="disableTOTP">
                            <div class="form-group">
                                <label for="disableCode">Code or Recovery Code</label>
                                <input 
                                    id="disableCode"
                                    type="text" 
                                    v-model="disableCode" 
                                    class="input font-mono"
                                    placeholder="Enter current code or recovery code"
                                    required
                                />
                            </div>
                            <div class="flex gap-2">
                                <button type="submit" class="btn btn-danger font-mono">
                                    Disable 2FA
                                </button>
                                <button type="button" class="btn font-mono" @click="showDisablePrompt = false; disableCode = ''">
                                    Cancel
                                </button>
                            </div>
                        </form>
                    </div>
                    <button v-else class="btn btn-danger font-mono" @click="triggerDisable">
                        Disable 2FA
                    </button>
                </div>

                <!-- State A: Disabled -->
                <div v-else class="mt-3">
                    <div class="mb-3 flex items-center gap-2">
                        <span class="badge badge-blocked">NOT SET</span>
                    </div>
                    <p class="muted-text" style="font-size: 0.85rem; margin-bottom: var(--s3);">
                        Protects your website login with a 6-digit code from an authenticator app; it does not affect the game launcher.
                    </p>
                    <button class="btn btn-primary font-mono" @click="startTOTPSetup">
                        Enable 2FA
                    </button>
                </div>
            </div>

            <!-- Danger Zone -->
            <div class="panel" style="border-color: var(--danger);">
                <div class="eyebrow" style="color: var(--danger-bright);">DANGER ZONE</div>
                <div class="mt-2 mb-3">
                    <p class="muted-text" style="font-size: 0.85rem;">
                        Permanently delete your account and all associated Minecraft players. This action is immediate and cannot be reversed.
                    </p>
                </div>
                <button class="btn btn-danger font-mono" @click="handleDeleteAccount">
                    Delete Account
                </button>
            </div>

            <!-- Reusable confirmation modal for every sensitive action -->
            <ConfirmModal 
                :show="showConfirm"
                :title="confirmTitle"
                :message="confirmMsg"
                :confirmLabel="confirmLabel"
                :variant="confirmVariant"
                @confirm="handleConfirm"
                @cancel="showConfirm = false"
            />
        </div>
    `
};

export default AccountView;