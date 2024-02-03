import { requireAuthentication } from '$lib/auth.js';

/** @type {import('./$types').PageLoad} */
export async function load(loadArgs) {
	const user = await requireAuthentication(loadArgs);
	const { fetch } = loadArgs;
	const res = await fetch('/api/video');
	const videos = res.json();
	return { videos, user };
}

export const ssr = false;
