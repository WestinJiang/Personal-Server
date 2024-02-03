import { browser } from '$app/environment';

/** @type {import('./$types').PageLoad} */
export async function load({ fetch }) {
	if (!browser)
		return {
			ntl: {
				logout: Promise.resolve({})
			}
		};
	// top-level promises are automatically resolved, so we intentionally
	// create a non-top-level (ntl) promise here (!?)
	else
		return {
			ntl: {
				logout: fetch('/api/logout', { method: 'POST' })
			}
		};
}
