<script>
	import { Container, Row } from 'sveltestrap';
	import { user } from '$lib/userstore';
</script>

<Container>
	{#if $user}
		<Row>
			<h1 class="mt-4">Welcome to a protected page</h1>
			<p>
				You are logged in as user <tt>{$user.sub}</tt>
			</p>
		</Row>
		<Row class="mt-1">
			<p>
				Your token was issued at {new Date($user.iat * 1000).toString()}, it expires {new Date(
					$user.exp * 1000
				).toString()}
			</p>
		</Row>
		<Row class="mt-1">
			<p>
				This page is "private" only inasmuch as the front-end does not display it to unauthenticated
				users. In a fully-fledged app, this page would now perform API requests that require
				authentication.
			</p>
		</Row>
	{:else}
		<Row>
			<h1 class="mt-4">Not logged in - you should not be seeing this on the client</h1>
			<div>
				<a href="/login">Log in</a>
			</div>
		</Row>
	{/if}
</Container>
