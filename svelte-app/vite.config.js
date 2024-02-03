import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// for development, proxy /api and *.mp4 to the pserv backend
const backend = 'http://localhost:10001';

export default defineConfig({
	plugins: [sveltekit()],
	ssr: {
        noExternal: ['@popperjs/core']
    },
    server: {
        proxy: {
            '/api': {
                target: backend,
                changeOrigin: true,
            },
            '^/.*.mp4$': {
                target: backend,
                changeOrigin: true,
            }
        }
    }
});
