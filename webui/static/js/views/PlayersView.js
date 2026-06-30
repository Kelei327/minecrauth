// SPDX-License-Identifier: Apache-2.0

const { ref, onMounted } = window.Vue;
import { api } from '../api.js';
import { addToast } from '../components/Toast.js';
import { PlayerCard } from '../components/PlayerCard.js';

export const PlayersView = {
    name: 'PlayersView',
    components: {
        PlayerCard
    },
    setup() {
        const players = ref([]);
        const loading = ref(true);

        // Form state
        const name = ref('');
        const uuid = ref('');
        const creating = ref(false);
        const showUuid = ref(false);

        // Custom UUID is optional and hidden by default to keep the form quiet.
        // Collapsing it clears any typed value so it is not submitted by accident.
        const toggleUuid = () => {
            showUuid.value = !showUuid.value;
            if (!showUuid.value) uuid.value = '';
        };

        const loadPlayers = async () => {
            loading.value = true;
            try {
                players.value = await api.get('/api/me/players');
            } catch (err) {
                console.error(err);
                addToast('Failed to load players: ' + err.message, 'danger');
            } finally {
                loading.value = false;
            }
        };

        const handleCreatePlayer = async () => {
            if (!name.value || name.value.trim() === '') {
                addToast('Player name is required', 'danger');
                return;
            }

            creating.value = true;
            try {
                await api.post('/api/me/players', {
                    name: name.value.trim(),
                    uuid: uuid.value.trim()
                });
                addToast('Minecraft player created successfully', 'success');
                name.value = '';
                uuid.value = '';
                await loadPlayers();
            } catch (err) {
                console.error(err);
                if (err.code === 'PlayerLimitReached') {
                    addToast('Player limit reached. Delete a player or ask an admin to raise the per-user limit.', 'danger');
                } else if (err.code === 'Conflict') {
                    addToast('That player name or UUID is already taken.', 'danger');
                } else if (err.code === 'InvalidPlayerName') {
                    addToast('Invalid player name. Use 2-16 letters, digits or underscores.', 'danger');
                } else if (err.code === 'InvalidUUID') {
                    addToast('That UUID is not valid.', 'danger');
                } else {
                    addToast('Failed to create player: ' + err.message, 'danger');
                }
            } finally {
                creating.value = false;
            }
        };

        onMounted(() => {
            loadPlayers();
        });

        return {
            players,
            loading,
            name,
            uuid,
            creating,
            showUuid,
            toggleUuid,
            loadPlayers,
            handleCreatePlayer
        };
    },
    template: `
        <div class="container">
            <div class="mb-4">
                <span class="eyebrow">DASHBOARD</span>
                <h1 class="font-pixel" style="font-size: 18px; margin-top: var(--s1); margin-bottom: var(--s1);">Minecraft Players</h1>
                <p class="muted-text">Manage your Minecraft player profiles, custom skins, and capes.</p>
            </div>

            <!-- Create Player Panel -->
            <div class="panel mb-4">
                <div class="eyebrow mb-3">CREATE NEW PROFILE</div>

                <form @submit.prevent="handleCreatePlayer" class="flex-col gap-3 mt-2">
                    <div class="form-group" style="margin-bottom: 0;">
                        <label for="playerName">Player Name</label>
                        <input 
                            id="playerName"
                            type="text" 
                            v-model="name" 
                            class="input"
                            placeholder="Steve"
                            required
                        />
                    </div>

                    <div v-if="!showUuid">
                        <button type="button" class="btn font-mono" style="font-size: 0.75rem;" @click="toggleUuid">
                            Set a custom UUID
                        </button>
                    </div>
                    <div v-else class="form-group" style="margin-bottom: 0;">
                        <label for="playerUUID" style="display: flex; justify-content: space-between; align-items: center;">
                            <span>Custom UUID</span>
                            <button type="button" class="btn font-mono" style="font-size: 0.65rem; padding: 2px 6px;" @click="toggleUuid">Remove</button>
                        </label>
                        <input 
                            id="playerUUID"
                            type="text" 
                            v-model="uuid" 
                            class="input font-mono"
                            placeholder="e.g. 8667ba71-b856-4004-a2ab-cfac0b2d352c"
                        />
                    </div>

                    <div style="display: flex; justify-content: flex-end;">
                        <button 
                            type="submit" 
                            class="btn btn-primary font-mono"
                            :disabled="creating"
                        >
                            {{ creating ? 'Creating...' : 'Create Player Profile' }}
                        </button>
                    </div>
                </form>
            </div>

            <!-- Players List -->
            <h2 class="font-pixel mb-3" style="font-size: 12px; color: var(--gold);">Your Profiles</h2>

            <div v-if="loading" class="panel text-center">
                <span class="font-mono">Loading profiles...</span>
            </div>

            <div v-else-if="players.length === 0" class="panel text-center">
                <p class="font-mono muted-text">No Minecraft players registered yet.</p>
                <p class="muted-text mt-2" style="font-size: 0.8rem;">Create your first profile above to start playing!</p>
            </div>

            <div v-else>
                <PlayerCard 
                    v-for="p in players" 
                    :key="p.id" 
                    :player="p"
                    @updated="loadPlayers"
                    @deleted="loadPlayers"
                />
            </div>
        </div>
    `
};

export default PlayersView;
