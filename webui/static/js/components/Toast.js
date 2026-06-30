// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

const { ref } = window.Vue;

export const toasts = ref([]);

let toastId = 0;

export function addToast(message, type = 'success', duration = 4000) {
    const id = ++toastId;
    toasts.value.push({ id, message, type });
    setTimeout(() => {
        toasts.value = toasts.value.filter(t => t.id !== id);
    }, duration);
}

export const ToastContainer = {
    name: 'ToastContainer',
    setup() {
        return { toasts };
    },
    template: `
        <div class="toast-container">
            <div 
                v-for="t in toasts" 
                :key="t.id" 
                class="toast"
                :class="'toast-' + t.type"
            >
                <div class="font-mono" style="font-size: 0.85rem; word-break: break-word;">
                    {{ t.message }}
                </div>
            </div>
        </div>
    `
};
