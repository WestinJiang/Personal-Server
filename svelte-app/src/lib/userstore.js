import { writable } from 'svelte/store';
import { getUser } from '$lib/auth';

function createUser() {
	const { subscribe, set } = writable(undefined, function start(set) {
		getUser(fetch).then((user) => set(user));
		return () => {};
	});

	return {
		subscribe,
		logout: () => set(null),
		login: (user) => {
			set(user);
		}
	};
}

export const user = createUser();
