// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

import { store } from '../store.js';
import { currentPath, navigate } from '../router.js';
import { api } from '../api.js';
import { GrassBlock } from './GrassBlock.js';
import { addToast } from './Toast.js';

export const AppHeader = {
    name: 'AppHeader',
    components: {
        GrassBlock
    },
    setup() {
        const handleLogout = async () => {
            try {
                await api.post('/web/api/logout');
                store.clearSession();
                addToast('Logged out successfully', 'success');
                navigate('/login');
            } catch (err) {
                console.error(err);
                addToast('Logout failed: ' + err.message, 'danger');
            }
        };

        return {
            store,
            currentPath,
            navigate,
            handleLogout
        };
    },
    template: `
        <header class="app-header">
            <div class="container flex items-center justify-between" style="padding: 0; max-width: 1000px; margin: 0 auto;">
                <!-- Logo & Brand -->
                <div class="flex items-center gap-2" style="cursor: pointer;" @click="navigate(store.currentUser ? '/players' : '/login')">
                    <GrassBlock />
                    <span class="font-pixel gold-text" style="font-size: 14px; user-select: none;">minecrauth</span>
                </div>

                <!-- Navigation Links -->
                <nav v-if="store.currentUser" class="flex items-center gap-4">
                    <a 
                        href="/players" 
                        class="nav-link" 
                        :class="{ active: currentPath === '/players' }"
                        @click.prevent="navigate('/players')"
                    >Players</a>
                    
                    <a 
                        href="/account" 
                        class="nav-link" 
                        :class="{ active: currentPath === '/account' }"
                        @click.prevent="navigate('/account')"
                    >Account</a>
                    
                    <a 
                        v-if="store.currentUser.is_admin"
                        href="/admin-ui" 
                        class="nav-link" 
                        :class="{ active: currentPath === '/admin-ui' }"
                        @click.prevent="navigate('/admin-ui')"
                    >Admin</a>

                    <button 
                        class="btn font-mono" 
                        style="padding: 4px 10px; font-size: 0.75rem;" 
                        @click="handleLogout"
                    >
                        Logout
                    </button>
                </nav>
            </div>
        </header>
    `
};

export default AppHeader;
