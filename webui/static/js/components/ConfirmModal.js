export const ConfirmModal = {
    name: 'ConfirmModal',
    props: {
        show: {
            type: Boolean,
            required: true
        },
        title: {
            type: String,
            default: 'Confirm Action'
        },
        message: {
            type: String,
            default: 'Are you sure you want to perform this action? This cannot be undone.'
        },
        confirmLabel: {
            type: String,
            default: 'Confirm'
        },
        variant: {
            type: String,
            default: 'primary' // 'primary' or 'danger'
        }
    },
    emits: ['confirm', 'cancel'],
    template: `
        <div v-if="show" class="modal-overlay" @click.self="$emit('cancel')">
            <div class="modal">
                <div class="modal-header">
                    <span class="font-pixel gold-text">{{ title }}</span>
                </div>
                <div class="modal-body">
                    <p style="font-size: 0.95rem; line-height: 1.4;">{{ message }}</p>
                </div>
                <div class="modal-footer">
                    <button class="btn font-mono" @click="$emit('cancel')">
                        Cancel
                    </button>
                    <button 
                        class="btn font-mono" 
                        :class="variant === 'danger' ? 'btn-danger' : 'btn-primary'"
                        @click="$emit('confirm')"
                    >
                        {{ confirmLabel }}
                    </button>
                </div>
            </div>
        </div>
    `
};

export default ConfirmModal;
