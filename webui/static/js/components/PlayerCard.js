const { ref, computed } = window.Vue;
import { store } from '../store.js';
import { api } from '../api.js';
import { addToast } from './Toast.js';
import { ConfirmModal } from './ConfirmModal.js';
import { SkinViewer3D } from './SkinViewer3D.js';

export const PlayerCard = {
    name: 'PlayerCard',
    components: {
        ConfirmModal,
        SkinViewer3D
    },
    props: {
        player: {
            type: Object,
            required: true
        }
    },
    emits: ['updated', 'deleted'],
    setup(props, { emit }) {
        const isRenaming = ref(false);
        const newName = ref(props.player.name);
        const showDeleteModal = ref(false);

        const isEditingUUID = ref(false);
        const newUUID = ref('');
        const showUUIDModal = ref(false);

        const skinInput = ref(null);
        const capeInput = ref(null);

        const canUpload = computed(() => {
            return store.config || { allowSkins: true, allowCapes: true };
        });

        // Inline Rename
        const startRename = () => {
            newName.value = props.player.name;
            isRenaming.value = true;
        };

        const cancelRename = () => {
            isRenaming.value = false;
        };

        const saveRename = async () => {
            if (!newName.value || newName.value.trim() === '') {
                addToast('Player name cannot be empty', 'danger');
                return;
            }
            try {
                await api.patch(`/api/me/players/${props.player.id}`, { name: newName.value.trim() });
                addToast('Player renamed successfully', 'success');
                isRenaming.value = false;
                emit('updated');
            } catch (err) {
                console.error(err);
                addToast('Failed to rename player: ' + err.message, 'danger');
            }
        };

        // UUID change
        const startEditUUID = () => {
            newUUID.value = '';
            isEditingUUID.value = true;
        };

        const cancelEditUUID = () => {
            isEditingUUID.value = false;
        };

        const confirmChangeUUID = async () => {
            try {
                await api.put(`/api/me/players/${props.player.id}/uuid`, { uuid: newUUID.value.trim() });
                addToast('Player UUID changed', 'success');
                showUUIDModal.value = false;
                isEditingUUID.value = false;
                emit('updated');
            } catch (err) {
                console.error(err);
                showUUIDModal.value = false;
                if (err.code === 'Conflict') {
                    addToast('That UUID is already taken by another player.', 'danger');
                } else if (err.code === 'InvalidUUID') {
                    addToast('That is not a valid UUID.', 'danger');
                } else {
                    addToast('Failed to change UUID: ' + err.message, 'danger');
                }
            }
        };

        // Player Delete
        const confirmDelete = async () => {
            try {
                await api.delete(`/api/me/players/${props.player.id}`);
                addToast('Player deleted successfully', 'success');
                showDeleteModal.value = false;
                emit('deleted');
            } catch (err) {
                console.error(err);
                addToast('Failed to delete player: ' + err.message, 'danger');
            }
        };

        // Skin actions
        const triggerSkinUpload = () => {
            if (skinInput.value) skinInput.value.click();
        };

        const handleSkinFile = async (event) => {
            const file = event.target.files[0];
            if (!file) return;

            try {
                const arrayBuffer = await file.arrayBuffer();
                await api.put(`/api/me/players/${props.player.id}/skin`, arrayBuffer, {
                    headers: { 'Content-Type': 'image/png' }
                });
                addToast('Skin uploaded successfully', 'success');
                emit('updated');
            } catch (err) {
                console.error(err);
                addToast('Skin upload failed: ' + err.message, 'danger');
            } finally {
                if (skinInput.value) skinInput.value.value = '';
            }
        };

        const removeSkin = async () => {
            try {
                await api.delete(`/api/me/players/${props.player.id}/skin`);
                addToast('Skin removed successfully', 'success');
                emit('updated');
            } catch (err) {
                console.error(err);
                addToast('Failed to remove skin: ' + err.message, 'danger');
            }
        };

        // Override the auto-detected arm model if it guessed wrong.
        const toggleModel = async () => {
            const next = props.player.skin_model === 'slim' ? 'classic' : 'slim';
            try {
                await api.put(`/api/me/players/${props.player.id}/skin/model`, { model: next });
                addToast('Skin model set to ' + next, 'success');
                emit('updated');
            } catch (err) {
                console.error(err);
                addToast('Failed to change model: ' + err.message, 'danger');
            }
        };

        // Cape actions
        const triggerCapeUpload = () => {
            if (capeInput.value) capeInput.value.click();
        };

        const handleCapeFile = async (event) => {
            const file = event.target.files[0];
            if (!file) return;

            try {
                const arrayBuffer = await file.arrayBuffer();
                await api.put(`/api/me/players/${props.player.id}/cape`, arrayBuffer, {
                    headers: { 'Content-Type': 'image/png' }
                });
                addToast('Cape uploaded successfully', 'success');
                emit('updated');
            } catch (err) {
                console.error(err);
                addToast('Cape upload failed: ' + err.message, 'danger');
            } finally {
                if (capeInput.value) capeInput.value.value = '';
            }
        };

        const removeCape = async () => {
            try {
                await api.delete(`/api/me/players/${props.player.id}/cape`);
                addToast('Cape removed successfully', 'success');
                emit('updated');
            } catch (err) {
                console.error(err);
                addToast('Failed to remove cape: ' + err.message, 'danger');
            }
        };

        const deleteMessage = computed(() =>
            `Are you sure you want to permanently delete player "${props.player.name}"?`
        );

        return {
            isRenaming,
            newName,
            showDeleteModal,
            canUpload,
            deleteMessage,
            isEditingUUID,
            newUUID,
            showUUIDModal,
            startEditUUID,
            cancelEditUUID,
            confirmChangeUUID,
            skinInput,
            capeInput,
            startRename,
            cancelRename,
            saveRename,
            confirmDelete,
            triggerSkinUpload,
            handleSkinFile,
            removeSkin,
            toggleModel,
            triggerCapeUpload,
            handleCapeFile,
            removeCape
        };
    },
    template: `
        <div class="panel" style="margin-bottom: var(--s4);">
            <!-- Player Header Row -->
            <div class="flex items-center justify-between mb-3" style="border-bottom: 2px solid var(--border); padding-bottom: var(--s2); gap: var(--s3); flex-wrap: wrap;">
                <template v-if="!isRenaming">
                    <div class="flex items-center gap-3" style="min-width: 0; flex: 1;">
                        <span class="font-pixel" style="font-size: 14px; color: var(--gold); overflow-wrap: anywhere; word-break: break-word;">{{ player.name }}</span>
                    </div>
                    <div class="flex items-center gap-2" style="flex-shrink: 0;">
                        <button class="btn font-mono" style="padding: 4px 10px; font-size: 0.75rem;" @click="startRename">Rename</button>
                        <button class="btn btn-danger font-mono" style="padding: 4px 10px; font-size: 0.75rem;" @click="showDeleteModal = true">Delete Player</button>
                    </div>
                </template>
                <template v-else>
                    <input
                        v-model="newName"
                        type="text"
                        class="input font-mono"
                        style="padding: 4px 8px; font-size: 0.85rem; max-width: 220px;"
                        @keyup.enter="saveRename"
                    />
                    <div class="flex items-center gap-2">
                        <button class="btn btn-primary font-mono" style="padding: 4px 10px; font-size: 0.75rem;" @click="saveRename">Save</button>
                        <button class="btn font-mono" style="padding: 4px 10px; font-size: 0.75rem;" @click="cancelRename">Cancel</button>
                    </div>
                </template>
            </div>

            <!-- UUID Row -->
            <div class="mb-4">
                <span class="eyebrow" style="margin-bottom: 2px;">UUID</span>
                <div v-if="!isEditingUUID" class="flex items-center gap-3" style="flex-wrap: wrap;">
                    <span class="font-mono" style="color: var(--muted); font-size: 0.8rem;">{{ player.uuid }}</span>
                    <button class="btn font-mono" style="padding: 2px 6px; font-size: 0.7rem;" @click="startEditUUID">Change UUID</button>
                </div>
                <div v-else class="flex-col gap-2" style="margin-top: 2px;">
                    <div class="flex items-center gap-2" style="flex-wrap: wrap;">
                        <input
                            v-model="newUUID"
                            type="text"
                            class="input font-mono"
                            style="padding: 2px 6px; font-size: 0.8rem; max-width: 320px;"
                            placeholder="Leave blank to auto-generate"
                        />
                        <button class="btn btn-danger font-mono" style="padding: 2px 6px; font-size: 0.7rem;" @click="showUUIDModal = true">Apply</button>
                        <button class="btn font-mono" style="padding: 2px 6px; font-size: 0.7rem;" @click="cancelEditUUID">Cancel</button>
                    </div>
                    <span class="font-mono" style="color: var(--gold); font-size: 0.7rem;">Changing the UUID resets this player's identity on every server (inventories, permissions, progress).</span>
                </div>
            </div>

            <!-- APPEARANCE: a compact 3D viewer on the left, grouped controls on the right -->
            <div class="panel-2">
                <div class="eyebrow">Appearance</div>

                <div class="flex gap-4 mt-2" style="flex-wrap: wrap; align-items: flex-start;">
                    <!-- Viewer: fixed, compact width so it does not dominate the full-width card -->
                    <div style="width: 220px; flex-shrink: 0;">
                        <SkinViewer3D
                            :skin-url="player.skin_hash ? '/textures/' + player.skin_hash : ''"
                            :cape-url="player.cape_hash ? '/textures/' + player.cape_hash : ''"
                            :model="player.skin_model || 'classic'"
                            :height="260"
                        />
                    </div>

                    <!-- Controls: Skin and Cape sections share an identical two-button grid so
                         everything lines up deterministically across rows. -->
                    <div class="flex-col gap-4" style="flex: 1; min-width: 240px;">
                        <!-- Skin controls -->
                        <div class="flex-col gap-2">
                            <span class="font-mono" style="font-size: 0.75rem; color: var(--gold);">SKIN</span>
                            <div v-if="canUpload.allowSkins" class="flex-col gap-2">
                                <div style="display: grid; grid-template-columns: 130px 90px; gap: var(--s2);">
                                    <input ref="skinInput" type="file" accept="image/png" style="display: none;" @change="handleSkinFile" />
                                    <button class="btn btn-primary font-mono" style="padding: 4px 0; font-size: 0.75rem;" @click="triggerSkinUpload">Upload Skin</button>
                                    <button v-if="player.skin_hash" class="btn btn-danger font-mono" style="padding: 4px 0; font-size: 0.75rem;" @click="removeSkin">Remove</button>
                                </div>
                                <!-- Arm model: secondary, grey, same width as Upload Skin and
                                     aligned right below it so the column stays tidy. -->
                                <div v-if="player.skin_hash" style="display: grid; grid-template-columns: 130px 90px; gap: var(--s2);">
                                    <button
                                        class="btn font-mono"
                                        style="padding: 4px 0; font-size: 0.75rem;"
                                        :title="'Detected as ' + (player.skin_model || 'classic') + '. Click to switch arm model.'"
                                        @click="toggleModel"
                                    >Arm: {{ player.skin_model || 'classic' }}</button>
                                </div>
                            </div>
                            <div v-else class="font-mono muted-text" style="font-size: 0.75rem;">Skin uploads are disabled by administrator.</div>
                        </div>

                        <!-- Cape controls -->
                        <div class="flex-col gap-2">
                            <span class="font-mono" style="font-size: 0.75rem; color: var(--gold);">CAPE</span>
                            <div v-if="canUpload.allowCapes" style="display: grid; grid-template-columns: 130px 90px; gap: var(--s2);">
                                <input ref="capeInput" type="file" accept="image/png" style="display: none;" @change="handleCapeFile" />
                                <button class="btn btn-primary font-mono" style="padding: 4px 0; font-size: 0.75rem;" @click="triggerCapeUpload">Upload Cape</button>
                                <button v-if="player.cape_hash" class="btn btn-danger font-mono" style="padding: 4px 0; font-size: 0.75rem;" @click="removeCape">Remove</button>
                            </div>
                            <div v-else class="font-mono muted-text" style="font-size: 0.75rem;">Cape uploads are disabled by administrator.</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Confirm Player Delete -->
            <ConfirmModal 
                :show="showDeleteModal"
                title="Delete Player Profile"
                :message="deleteMessage"
                confirmLabel="Delete"
                variant="danger"
                @confirm="confirmDelete"
                @cancel="showDeleteModal = false"
            />

            <!-- Confirm UUID Change -->
            <ConfirmModal
                :show="showUUIDModal"
                title="Change Player UUID"
                message="Changing this player's UUID makes it a different identity on every Minecraft server: inventories, permissions and progress tied to the old UUID will no longer belong to this player. Continue?"
                confirmLabel="Change UUID"
                variant="danger"
                @confirm="confirmChangeUUID"
                @cancel="showUUIDModal = false"
            />
        </div>
    `
};

export default PlayerCard;
