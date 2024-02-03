import { browser } from '$app/environment';
import { goto } from '$app/navigation';
import { success } from '$lib/toast';

export async function getUser(fetch) {
	if (browser) {
		const res = await fetch(`/api/login`);
		const user = await res.json();
		success(`Server said: ${JSON.stringify(user)}`);
		if (!('sub' in user)) return null;
		return user;
	} else {
		return {};
	}
}

export async function requireAuthentication({ fetch, route }) {
	if (browser) {
		const { id: dstpath } = route;
		try {
			const user = await getUser(fetch);
			if (user === null) throw new Error('user not logged in');
			return user;
		} catch (er) {
			console.log(`visiting ${dstpath} which requires authentication, now redirecting to /login`);
			goto('/login?next=' + encodeURIComponent(dstpath));
			return {};
		}
	} else {
		return {};
	}
}
