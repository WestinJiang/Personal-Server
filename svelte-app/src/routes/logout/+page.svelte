<script>
	import { user } from '$lib/userstore';
	import { goto } from '$app/navigation';
	import { browser } from '$app/environment';
	/** @type {import('./$types').PageData} */
	export let data;
	data.ntl.logout.then(() => {
		user.logout();
		if (browser) goto('/');
	});
</script>

{#await data.ntl.logout}
	<div>Logging out...</div>
{:then r}
	{#if r.ok}
		<div>Logged out <a href="/">click here if it doesn't redirect</a></div>
	{:else}
		<div>Logout failed</div>
	{/if}
{/await}
