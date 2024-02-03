import { requireAuthentication } from '$lib/auth.js';

/** @type {import('./$types').LayoutLoad} */
export async function load(loadArgs) {
	return requireAuthentication(loadArgs);
}

export const prerender = false;
