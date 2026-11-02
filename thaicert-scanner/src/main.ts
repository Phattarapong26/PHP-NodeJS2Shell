// Fonts + icon font (bundled locally so the desktop shell works offline).
import '@fontsource/plus-jakarta-sans/300.css';
import '@fontsource/plus-jakarta-sans/400.css';
import '@fontsource/plus-jakarta-sans/500.css';
import '@fontsource/plus-jakarta-sans/600.css';
import '@fontsource/plus-jakarta-sans/700.css';
import '@fontsource/plus-jakarta-sans/800.css';
import '@fontsource/sarabun/300.css';
import '@fontsource/sarabun/400.css';
import '@fontsource/sarabun/500.css';
import '@fontsource/sarabun/600.css';
import '@fontsource/sarabun/700.css';
import './lib/vendor/phosphor/regular/style.css';
import './lib/vendor/phosphor/bold/style.css';
import './lib/vendor/phosphor/fill/style.css';
import './lib/vendor/phosphor/duotone/style.css';

// Tailwind layers + legacy application styles.
import './lib/styles/app.css';

import { mount } from 'svelte';
import App from './App.svelte';

const target = document.getElementById('app');
if (!target) throw new Error('#app mount point not found');

const app = mount(App, { target });

export default app;
