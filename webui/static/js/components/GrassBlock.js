// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// GrassBlock renders the minecrauth grass-block logo. The artwork lives in a
// reusable standalone file at /static/images/grass-block.svg so it can be shared
// (favicon, docs, etc.) instead of being embedded in the component source.
export const GrassBlock = {
    name: 'GrassBlock',
    template: `
        <img
            src="/static/images/grass-block.svg"
            class="grass-block-svg pixelated"
            width="28"
            height="28"
            alt="minecrauth"
            style="display: block;"
        />
    `
};
export default GrassBlock;
