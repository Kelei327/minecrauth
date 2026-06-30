// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

const { ref, onMounted, onBeforeUnmount, watch, nextTick } = window.Vue;

// Default skin used when a player has no skin of its own, mirroring Minecraft's
// behaviour (a skinless player shows the default character). Having a body to render
// also lets the cape show up when only a cape is set.
const DEFAULT_SKIN = '/static/vendor/default-skin.png';

// SkinViewer3D renders a rotating, walking 3D preview of a Minecraft skin (and cape)
// using the vendored skinview3d bundle (Three.js included).
//
// When WebGL is unavailable (some privacy browsers, no hardware acceleration, old
// devices) it degrades to a 2D pixel-art preview: the face cropped from the skin plus,
// if present, the front of the cape.
//
// The viewer is fully rebuilt whenever the skin, cape or model changes. Rebuilding is
// cheap and avoids a class of state bugs that a long-lived viewer is prone to.
export const SkinViewer3D = {
    name: 'SkinViewer3D',
    props: {
        skinUrl: { type: String, default: '' },
        capeUrl: { type: String, default: '' },
        model: { type: String, default: 'classic' },
        height: { type: Number, default: 300 },
    },
    setup(props) {
        const root = ref(null);
        const canvas = ref(null);
        const faceCanvas = ref(null);
        const failed = ref(false);
        let viewer = null;
        let ro = null;

        const effectiveSkin = () => props.skinUrl || DEFAULT_SKIN;

        // The viewer width tracks the container so it fills the box horizontally.
        const viewerWidth = () => {
            const w = root.value ? root.value.clientWidth : 0;
            return w > 0 ? w : 320;
        };

        const disposeViewer = () => {
            if (viewer) {
                try { viewer.dispose(); } catch (e) { /* ignore */ }
                viewer = null;
            }
        };

        // drawFallback renders a 2D preview when WebGL is unavailable: the face cropped
        // from the (effective) skin, plus the front of the cape when one is set.
        const drawFallback = () => {
            const fc = faceCanvas.value;
            if (!fc) return;
            const cell = 88;          // size of each preview cell
            const gap = 28;           // breathing room between face and cape
            const hasCape = !!props.capeUrl;
            const capeW = hasCape ? Math.round(cell * 10 / 16) : 0; // cape front is 10x16
            // The canvas fills the viewer box; the content is centred within it.
            fc.width = viewerWidth();
            fc.height = props.height;
            const ctx = fc.getContext('2d');
            if (!ctx) return;
            ctx.imageSmoothingEnabled = false;

            const contentW = cell + (hasCape ? gap + capeW : 0);
            const ox = Math.round((fc.width - contentW) / 2);
            const oy = Math.round((fc.height - cell) / 2);

            const skinImg = new Image();
            skinImg.onload = () => {
                // Base face (8,8) + hat overlay (40,8), each 8x8, scaled up.
                ctx.drawImage(skinImg, 8, 8, 8, 8, ox, oy, cell, cell);
                ctx.drawImage(skinImg, 40, 8, 8, 8, ox, oy, cell, cell);
            };
            skinImg.src = effectiveSkin();

            if (hasCape) {
                const capeX = ox + cell + gap;
                const capeImg = new Image();
                capeImg.onload = () => {
                    // Cape front is a 10x16 region at (1,1) in the 64x32 cape texture.
                    ctx.drawImage(capeImg, 1, 1, 10, 16, capeX, oy, capeW, cell);
                };
                capeImg.src = props.capeUrl;
            }
        };

        // build (re)creates the 3D viewer, or falls back to the 2D preview when WebGL or
        // the library is unavailable.
        const build = () => {
            disposeViewer();
            const lib = window.skinview3d;
            if (!lib || !lib.SkinViewer || !canvas.value) {
                failed.value = true;
                nextTick(drawFallback);
                return;
            }
            try {
                viewer = new lib.SkinViewer({
                    canvas: canvas.value,
                    width: viewerWidth(),
                    height: props.height,
                    skin: effectiveSkin(),
                    model: props.model === 'slim' ? 'slim' : 'default',
                    cape: props.capeUrl || undefined,
                });
                failed.value = false;
                viewer.zoom = 0.9;
                viewer.autoRotate = true;
                viewer.autoRotateSpeed = 0.6;
                if (lib.WalkingAnimation) {
                    viewer.animation = new lib.WalkingAnimation();
                    viewer.animation.speed = 0.7;
                }
            } catch (e) {
                console.error('SkinViewer3D init failed', e);
                failed.value = true;
                nextTick(drawFallback);
            }
        };

        onMounted(() => {
            build();
            // Rebuild on container resize so the viewer keeps filling the box width.
            if (typeof ResizeObserver !== 'undefined' && root.value) {
                let lastW = viewerWidth();
                ro = new ResizeObserver(() => {
                    const w = viewerWidth();
                    if (Math.abs(w - lastW) > 4) {
                        lastW = w;
                        build();
                    }
                });
                ro.observe(root.value);
            }
        });
        watch(() => [props.skinUrl, props.capeUrl, props.model], build);
        onBeforeUnmount(() => {
            if (ro) { ro.disconnect(); ro = null; }
            disposeViewer();
        });

        return { root, canvas, faceCanvas, failed };
    },
    template: `
        <div class="skin-viewer-3d" ref="root" :style="{ height: height + 'px' }">
            <canvas v-show="!failed" ref="canvas"></canvas>
            <div v-if="failed" class="skin-viewer-fallback">
                <canvas ref="faceCanvas" class="pixelated skin-face"></canvas>
            </div>
        </div>
    `
};

export default SkinViewer3D;
