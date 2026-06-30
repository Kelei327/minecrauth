// SPDX-License-Identifier: Apache-2.0

const { ref, computed, onMounted } = window.Vue;
import { store } from '../store.js';
import { navigate } from '../router.js';
import { api } from '../api.js';
import { addToast } from '../components/Toast.js';
import { ConfirmModal } from '../components/ConfirmModal.js';

export const AdminView = {
    name: 'AdminView',
    components: {
        ConfirmModal
    },
    setup() {
        const users = ref([]);
        const loading = ref(true);

        // Create user form state
        const email = ref('');
        const password = ref('');
        const isAdmin = ref(false);
        const creating = ref(false);

        // Client-side pagination state
        const currentPage = ref(1);
        const pageSize = 10;

        // Invite management state
        const invites = ref([]);
        const inviteTTL = ref('168');
        const creatingInvite = ref(false);

        // Confirm modal state
        const showConfirm = ref(false);
        const confirmTitle = ref('');
        const confirmMsg = ref('');
        const confirmLabel = ref('Confirm');
        const confirmVariant = ref('primary');
        const confirmAction = ref(null);

        // Tab state
        const activeTab = ref('users');

        // Backup & Restore state
        const downloading = ref(false);
        const restoreInput = ref(null);
        const restoreFile = ref(null);
        const restoreFileName = ref('');
        const restoring = ref(false);
        const restoreStaged = ref(false);

        const loadUsers = async () => {
            loading.value = true;
            try {
                const data = await api.get('/admin/users');
                users.value = data || [];
                // Reset page if it exceeds bounds after update
                const maxPage = Math.ceil(users.value.length / pageSize) || 1;
                if (currentPage.value > maxPage) {
                    currentPage.value = maxPage;
                }
            } catch (err) {
                console.error(err);
                addToast('Failed to load user list: ' + err.message, 'danger');
            } finally {
                loading.value = false;
            }
        };

        const loadInvites = async () => {
            try {
                const data = await api.get('/admin/invites');
                invites.value = data || [];
            } catch (err) {
                console.error(err);
                addToast('Failed to load invites: ' + err.message, 'danger');
            }
        };

        const setTab = (tab) => {
            activeTab.value = tab;
        };

        const downloadBackup = async () => {
            downloading.value = true;
            try {
                const res = await fetch('/admin/backup', { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } });
                if (!res.ok) { addToast('Failed to create backup (' + res.status + ')', 'danger'); return; }
                const blob = await res.blob();
                const cd = res.headers.get('Content-Disposition') || '';
                const m = cd.match(/filename=\"?([^\";]+)\"?/);
                const filename = (m && m[1]) || 'minecrauth-backup.tar.gz';
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = filename;
                document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
                addToast('Backup downloaded', 'success');
            } catch (e) { console.error(e); addToast('Backup failed: ' + e.message, 'danger'); }
            finally { downloading.value = false; }
        };

        const triggerRestoreFilePick = () => {
            if (restoreInput.value) {
                restoreInput.value.click();
            }
        };

        const onRestoreFileChange = (event) => {
            const file = event.target.files[0];
            if (file) {
                restoreFile.value = file;
                restoreFileName.value = file.name;
            }
        };

        const doRestore = async () => {
            if (!restoreFile.value) return;
            restoring.value = true;
            try {
                const buf = await restoreFile.value.arrayBuffer();
                const headers = { 'Content-Type': 'application/gzip', 'X-Requested-With': 'XMLHttpRequest' };
                if (store.csrfToken) headers['X-CSRF-Token'] = store.csrfToken;
                const res = await fetch('/admin/restore', { method: 'POST', credentials: 'same-origin', headers, body: buf });
                if (!res.ok) {
                    let msg = 'Restore failed (' + res.status + ')';
                    try {
                        const j = await res.json();
                        if (j && j.error === 'InvalidBackup') {
                            msg = 'That file is not a valid minecrauth backup.';
                        } else if (j && j.message) {
                            msg = j.message;
                        }
                    } catch (e) {}
                    addToast(msg, 'danger');
                    return;
                }
                restoreStaged.value = true;
                restoreFile.value = null;
                restoreFileName.value = '';
                if (restoreInput.value) {
                    restoreInput.value.value = '';
                }
                addToast('Restore staged. Restart the server to apply.', 'success');
            } catch (e) {
                console.error(e);
                addToast('Restore failed: ' + e.message, 'danger');
            } finally {
                restoring.value = false;
            }
        };

        const triggerRestore = () => {
            confirmTitle.value = 'Restore From Backup';
            confirmMsg.value = 'Restore will overwrite ALL current data with the backup. You must restart the server afterwards. Continue?';
            confirmLabel.value = 'Restore';
            confirmVariant.value = 'danger';
            confirmAction.value = () => doRestore();
            showConfirm.value = true;
        };

        const handleCreateInvite = async () => {
            creatingInvite.value = true;
            try {
                // The form holds a TTL in hours; the API expects seconds (0 = never expires).
                const hours = parseInt(inviteTTL.value, 10);
                const ttlSeconds = Number.isFinite(hours) && hours > 0 ? hours * 3600 : 0;
                const inv = await api.post('/admin/invites', { ttlSeconds });
                addToast('Invite created', 'success');
                if (inv && inv.code) {
                    copyInviteLink(inv.code);
                }
                await loadInvites();
            } catch (err) {
                console.error(err);
                addToast('Failed to create invite: ' + err.message, 'danger');
            } finally {
                creatingInvite.value = false;
            }
        };

        const inviteLink = (code) => `${window.location.origin}/login?invite=${encodeURIComponent(code)}`;

        const copyInviteLink = (code) => {
            const link = inviteLink(code);
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(link)
                    .then(() => addToast('Invite link copied to clipboard', 'success'))
                    .catch(() => addToast('Invite link: ' + link, 'success'));
            } else {
                addToast('Invite link: ' + link, 'success');
            }
        };

        const handleDeleteInvite = async (code) => {
            try {
                await api.delete(`/admin/invites/${encodeURIComponent(code)}`);
                addToast('Invite revoked', 'success');
                await loadInvites();
            } catch (err) {
                console.error(err);
                addToast('Failed to revoke invite: ' + err.message, 'danger');
            }
        };

        const handleCreateUser = async () => {
            if (!email.value || email.value.trim() === '') {
                addToast('Email address is required', 'danger');
                return;
            }
            if (!password.value) {
                addToast('Password is required', 'danger');
                return;
            }

            creating.value = true;
            try {
                await api.post('/admin/users', {
                    email: email.value.trim(),
                    password: password.value,
                    isAdmin: isAdmin.value
                });
                addToast('User account created successfully', 'success');
                email.value = '';
                password.value = '';
                isAdmin.value = false;
                await loadUsers();
            } catch (err) {
                console.error(err);
                addToast('Failed to create user: ' + err.message, 'danger');
            } finally {
                creating.value = false;
            }
        };

        // User Action Executions
        const executeSetAdmin = async (userId, status) => {
            try {
                await api.put(`/admin/users/${userId}/admin`, { isAdmin: status });
                addToast(status ? 'User promoted to Administrator' : 'Administrator privileges removed', 'success');
                await loadUsers();
            } catch (err) {
                console.error(err);
                addToast('Failed to change admin privileges: ' + err.message, 'danger');
            }
        };

        const executeSetBlocked = async (userId, status) => {
            try {
                await api.put(`/admin/users/${userId}/blocked`, { blocked: status });
                addToast(status ? 'User account blocked' : 'User account unblocked', 'success');
                await loadUsers();
            } catch (err) {
                console.error(err);
                addToast('Failed to update blocked status: ' + err.message, 'danger');
            }
        };

        const executeDeleteUser = async (userId) => {
            try {
                await api.delete(`/admin/users/${userId}`);
                addToast('User deleted successfully', 'success');
                await loadUsers();
            } catch (err) {
                console.error(err);
                addToast('Failed to delete user: ' + err.message, 'danger');
            }
        };

        const handleImpersonate = async (user) => {
            try {
                await api.post(`/admin/users/${user.id}/impersonate`);
                await store.bootstrap();
                addToast(`Impersonating ${user.email} now`, 'success');
                navigate('/players');
            } catch (err) {
                console.error(err);
                addToast('Impersonation failed: ' + err.message, 'danger');
            }
        };

        // Confirm Dialog Triggers
        const triggerDemote = (user) => {
            confirmTitle.value = 'Demote Administrator';
            confirmMsg.value = `Are you sure you want to demote "${user.email}" and remove their administrative permissions?`;
            confirmLabel.value = 'Demote';
            confirmVariant.value = 'danger';
            confirmAction.value = () => executeSetAdmin(user.id, false);
            showConfirm.value = true;
        };

        const triggerBlock = (user) => {
            confirmTitle.value = 'Block User Account';
            confirmMsg.value = `Are you sure you want to block "${user.email}"? Blocked users are immediately disconnected and cannot sign in.`;
            confirmLabel.value = 'Block';
            confirmVariant.value = 'danger';
            confirmAction.value = () => executeSetBlocked(user.id, true);
            showConfirm.value = true;
        };

        const triggerDelete = (user) => {
            confirmTitle.value = 'Delete User Account';
            confirmMsg.value = `Are you sure you want to delete user "${user.email}"? This will permanently delete their account and ALL of their Minecraft player profiles. This cannot be undone!`;
            confirmLabel.value = 'Delete Permanently';
            confirmVariant.value = 'danger';
            confirmAction.value = () => executeDeleteUser(user.id);
            showConfirm.value = true;
        };

        // Direct Actions
        const handlePromote = (user) => {
            executeSetAdmin(user.id, true);
        };

        const handleUnblock = (user) => {
            executeSetBlocked(user.id, false);
        };

        const handleResetPassword = async (user) => {
            try {
                const res = await api.post(`/admin/users/${user.id}/reset-token`);
                const link = res.resetUrl;
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(link)
                        .then(() => addToast('Reset link copied to clipboard (valid 1 hour)', 'success'))
                        .catch(() => addToast('Reset link: ' + link, 'success'));
                } else {
                    addToast('Reset link: ' + link, 'success');
                }
            } catch (err) {
                console.error(err);
                addToast('Failed to generate reset link: ' + err.message, 'danger');
            }
        };

        const handleConfirm = () => {
            if (confirmAction.value) {
                confirmAction.value();
            }
            showConfirm.value = false;
            confirmAction.value = null;
        };

        // Header copy that adapts to the active tab.
        const tabTitle = computed(() => {
            if (activeTab.value === 'invites') return 'Invitations';
            if (activeTab.value === 'backup') return 'Backup & Restore';
            return 'User Management';
        });
        const tabSubtitle = computed(() => {
            if (activeTab.value === 'invites') {
                return 'Generate and revoke single-use registration invite links.';
            }
            if (activeTab.value === 'backup') {
                return 'Download a full snapshot of the server state, or restore one.';
            }
            return 'Monitor system accounts, adjust roles, enforce restrictions, and impersonate sessions.';
        });

        // Pagination computed values
        const totalPages = computed(() => {
            return Math.ceil(users.value.length / pageSize) || 1;
        });

        const paginatedUsers = computed(() => {
            const start = (currentPage.value - 1) * pageSize;
            const end = start + pageSize;
            return users.value.slice(start, end);
        });

        const prevPage = () => {
            if (currentPage.value > 1) {
                currentPage.value--;
            }
        };

        const nextPage = () => {
            if (currentPage.value < totalPages.value) {
                currentPage.value++;
            }
        };

        // Formatting utilities
        const formatDate = (dateStr) => {
            if (!dateStr) return 'N/A';
            const d = new Date(dateStr);
            return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        };

        onMounted(() => {
            loadUsers();
            loadInvites();
        });

        return {
            users,
            loading,
            email,
            password,
            isAdmin,
            creating,
            currentPage,
            totalPages,
            paginatedUsers,
            showConfirm,
            confirmTitle,
            confirmMsg,
            confirmLabel,
            confirmVariant,
            prevPage,
            nextPage,
            formatDate,
            handleCreateUser,
            invites,
            inviteTTL,
            creatingInvite,
            handleCreateInvite,
            handleDeleteInvite,
            copyInviteLink,
            handleImpersonate,
            triggerDemote,
            triggerBlock,
            triggerDelete,
            handlePromote,
            handleUnblock,
            handleResetPassword,
            handleConfirm,
            store,
            activeTab,
            setTab,
            tabTitle,
            tabSubtitle,
            downloading,
            downloadBackup,
            restoreInput,
            restoreFile,
            restoreFileName,
            restoring,
            restoreStaged,
            triggerRestoreFilePick,
            onRestoreFileChange,
            triggerRestore
        };
    },
    template: `
        <div class="container">
            <div class="mb-4">
                <span class="eyebrow">ADMINISTRATION</span>
                <h1 class="font-pixel" style="font-size: 18px; margin-top: var(--s1); margin-bottom: var(--s1);">{{ tabTitle }}</h1>
                <p class="muted-text">{{ tabSubtitle }}</p>
            </div>

            <!-- Tab Bar -->
            <div class="flex gap-2 mb-4" role="tablist">
                <button class="btn font-mono" :class="{ active: activeTab === 'users' }" :style="activeTab === 'users' ? 'color: var(--gold);' : ''" @click="setTab('users')">Users</button>
                <button class="btn font-mono" :class="{ active: activeTab === 'invites' }" :style="activeTab === 'invites' ? 'color: var(--gold);' : ''" @click="setTab('invites')">Invites</button>
                <button class="btn font-mono" :class="{ active: activeTab === 'backup' }" :style="activeTab === 'backup' ? 'color: var(--gold);' : ''" @click="setTab('backup')">Backup</button>
            </div>

            <!-- Users Tab -->
            <div v-show="activeTab === 'users'" class="grid grid-cols-2 gap-4">
                <!-- Create User Panel -->
                <div style="grid-column: span 2 / span 2;">
                    <div class="panel">
                        <div class="eyebrow mb-3">SYSTEM REGISTRATION</div>
                        
                        <form @submit.prevent="handleCreateUser" class="grid grid-cols-2 gap-3">
                            <div class="form-group" style="grid-column: span 1;">
                                <label for="adminEmail">Email Address</label>
                                <input 
                                    id="adminEmail"
                                    type="email" 
                                    v-model="email" 
                                    class="input"
                                    placeholder="steve@minecraft.net"
                                    required
                                />
                            </div>

                            <div class="form-group" style="grid-column: span 1;">
                                <label for="adminPassword">Password</label>
                                <input 
                                    id="adminPassword"
                                    type="password" 
                                    v-model="password" 
                                    class="input"
                                    placeholder="••••••••"
                                    required
                                />
                            </div>

                            <div class="form-group" style="grid-column: span 2; margin-bottom: 0;">
                                <label class="checkbox-container">
                                    <input type="checkbox" v-model="isAdmin" />
                                    <span class="checkbox-box"></span>
                                    <span>Grant Administrator Privileges</span>
                                </label>
                            </div>

                            <div style="grid-column: span 2;" class="mt-2 text-right">
                                <button 
                                    type="submit" 
                                    class="btn btn-primary font-mono"
                                    :disabled="creating"
                                >
                                    {{ creating ? 'Creating...' : 'Create Account' }}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- User List -->
                <div style="grid-column: span 2 / span 2;" class="flex-col gap-3">
                    <h2 class="font-pixel mb-2" style="font-size: 12px; color: var(--gold);">Registered Accounts</h2>
                    
                    <div v-if="loading" class="panel text-center">
                        <span class="font-mono">Loading user directory...</span>
                    </div>

                    <div v-else>
                        <div class="table-container">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Email Address</th>
                                        <th>Status</th>
                                        <th>Created At</th>
                                        <th class="text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="u in paginatedUsers" :key="u.id">
                                        <td>
                                            <div class="font-mono" style="font-weight: bold;">{{ u.email }}</div>
                                            <div class="muted-text" style="font-size: 0.75rem;">ID: {{ u.id }}</div>
                                        </td>
                                        <td>
                                            <div class="flex gap-1" style="flex-wrap: wrap;">
                                                <span v-if="u.is_admin" class="badge badge-admin">Admin</span>
                                                <span v-if="u.blocked" class="badge badge-blocked">Blocked</span>
                                                <span v-if="!u.is_admin && !u.blocked" class="badge badge-active">Normal</span>
                                            </div>
                                        </td>
                                        <td class="font-mono text-muted" style="font-size: 0.8rem;">
                                            {{ formatDate(u.created_at) }}
                                        </td>
                                        <td>
                                            <div class="flex gap-2 justify-between" style="justify-content: flex-end;">
                                                <!-- Impersonate -->
                                                <button 
                                                    v-if="u.id !== store.currentUser?.id && !u.blocked"
                                                    class="btn font-mono" 
                                                    style="padding: 2px 6px; font-size: 0.7rem;" 
                                                    @click="handleImpersonate(u)"
                                                >
                                                    Impersonate
                                                </button>

                                                <!-- Promote / Demote -->
                                                <button 
                                                    v-if="u.id !== store.currentUser?.id"
                                                    class="btn font-mono"
                                                    style="padding: 2px 6px; font-size: 0.7rem;"
                                                    @click="u.is_admin ? triggerDemote(u) : handlePromote(u)"
                                                >
                                                    {{ u.is_admin ? 'Demote' : 'Promote' }}
                                                </button>

                                                <!-- Block / Unblock -->
                                                <button 
                                                    v-if="u.id !== store.currentUser?.id"
                                                    class="btn font-mono"
                                                    style="padding: 2px 6px; font-size: 0.7rem;"
                                                    @click="u.blocked ? handleUnblock(u) : triggerBlock(u)"
                                                >
                                                    {{ u.blocked ? 'Unblock' : 'Block' }}
                                                </button>

                                                <!-- Delete -->
                                                <button 
                                                    v-if="u.id !== store.currentUser?.id"
                                                    class="btn btn-danger font-mono"
                                                    style="padding: 2px 6px; font-size: 0.7rem;"
                                                    @click="triggerDelete(u)"
                                                >
                                                    Delete
                                                </button>

                                                <!-- Reset Password -->
                                                <button 
                                                    class="btn font-mono"
                                                    style="padding: 2px 6px; font-size: 0.7rem;"
                                                    @click="handleResetPassword(u)"
                                                >
                                                    Reset Password
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>

                        <!-- Pagination controls -->
                        <div class="pagination">
                            <button class="btn font-mono" style="padding: 4px 8px;" :disabled="currentPage === 1" @click="prevPage">
                                &lt; Prev
                            </button>
                            <span class="font-mono" style="font-size: 0.85rem;">
                                Page {{ currentPage }} of {{ totalPages }}
                            </span>
                            <button class="btn font-mono" style="padding: 4px 8px;" :disabled="currentPage === totalPages" @click="nextPage">
                                Next &gt;
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Invites Tab -->
            <div v-show="activeTab === 'invites'" class="grid grid-cols-2 gap-4">
                <!-- Create Invite Panel -->
                <div style="grid-column: span 2 / span 2;">
                    <div class="panel">
                        <div class="eyebrow mb-3">SELF-SERVICE REGISTRATION</div>
                        <p class="muted-text" style="font-size: 0.8rem; margin-bottom: var(--s3);">Generate an invite link so a new person can register their own account. Share the link; it can be used once.</p>

                        <div class="flex items-center gap-3" style="flex-wrap: wrap;">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label for="inviteTTL">Expires in (hours, 0 = never)</label>
                                <input id="inviteTTL" type="number" min="0" v-model="inviteTTL" class="input font-mono" style="max-width: 160px;" />
                            </div>
                            <button class="btn btn-primary font-mono" style="align-self: flex-end;" :disabled="creatingInvite" @click="handleCreateInvite">
                                {{ creatingInvite ? 'Generating...' : 'Generate Invite' }}
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Invite List -->
                <div style="grid-column: span 2 / span 2;" class="flex-col gap-3">
                    <h2 class="font-pixel mb-2" style="font-size: 12px; color: var(--gold);">Active Invites</h2>

                    <div v-if="invites.length === 0" class="panel font-mono muted-text" style="font-size: 0.8rem;">No active invites.</div>
                    <div v-else class="table-container">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Code</th>
                                    <th>Status</th>
                                    <th>Expires</th>
                                    <th class="text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="inv in invites" :key="inv.code">
                                    <td><span class="font-mono" style="font-size: 0.8rem;">{{ inv.code }}</span></td>
                                    <td>
                                        <span v-if="inv.used_by" class="badge badge-blocked">Used</span>
                                        <span v-else class="badge badge-active">Available</span>
                                    </td>
                                    <td><span class="font-mono" style="font-size: 0.75rem;">{{ inv.expires_at ? formatDate(inv.expires_at) : 'Never' }}</span></td>
                                    <td class="text-right">
                                        <button v-if="!inv.used_by" class="btn font-mono" style="padding: 2px 6px; font-size: 0.7rem;" @click="copyInviteLink(inv.code)">Copy Link</button>
                                        <button class="btn btn-danger font-mono" style="padding: 2px 6px; font-size: 0.7rem;" @click="handleDeleteInvite(inv.code)">Revoke</button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Backup Tab -->
            <div v-show="activeTab === 'backup'" class="grid grid-cols-2 gap-4">
                <!-- Download Backup Panel -->
                <div style="grid-column: span 2 / span 2;">
                    <div class="panel">
                        <div class="eyebrow mb-3">BACKUP</div>
                        <p class="muted-text mb-4" style="font-size: 0.85rem; line-height: 1.4;">
                            A full snapshot of the server state: database, RSA signing key, player textures, and config.
                            <br/><br/>
                            <strong class="danger-text">SECURITY WARNING:</strong> it holds the private key and password hashes. Keep it somewhere safe.
                        </p>
                        <div>
                            <button class="btn btn-primary font-mono" :disabled="downloading" @click="downloadBackup">
                                {{ downloading ? 'Downloading...' : 'Download Backup' }}
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Restore Backup Panel -->
                <div style="grid-column: span 2 / span 2;">
                    <div class="panel" style="border-color: var(--danger);">
                        <div class="eyebrow mb-3" style="color: var(--danger-bright);">RESTORE (DANGER)</div>
                        <p class="muted-text mb-4" style="font-size: 0.85rem; line-height: 1.4;">
                            Restoring will overwrite ALL current server data (accounts, players, settings) with the contents of the backup archive.
                            The server must be restarted afterwards to apply the change.
                        </p>

                        <div v-if="restoreStaged" class="panel mb-4" style="border-color: var(--gold); background: rgba(212, 175, 55, 0.1);">
                            <span class="font-pixel gold-text" style="font-size: 11px; display: block; margin-bottom: 4px;">RESTORE STAGED</span>
                            <p class="muted-text mb-0" style="font-size: 0.8rem; color: #fff;">
                                Restore staged successfully. Restart the minecrauth server now to apply it.
                            </p>
                        </div>

                        <div class="flex items-center gap-3" style="flex-wrap: wrap;">
                            <input type="file" ref="restoreInput" style="display: none;" accept=".gz,.tar.gz,application/gzip" @change="onRestoreFileChange" />
                            <button class="btn font-mono" @click="triggerRestoreFilePick">
                                Choose Backup File...
                            </button>
                            <span v-if="restoreFileName" class="font-mono" style="font-size: 0.8rem;">
                                Selected: {{ restoreFileName }}
                            </span>
                            <span v-else class="font-mono muted-text" style="font-size: 0.8rem;">
                                No file chosen
                            </span>
                        </div>

                        <div class="mt-4 text-right">
                            <button class="btn btn-danger font-mono" :disabled="!restoreFile || restoring" @click="triggerRestore">
                                {{ restoring ? 'Restoring...' : 'Restore (requires restart)' }}
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Dynamic Reusable Confirm Modal -->
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

export default AdminView;
