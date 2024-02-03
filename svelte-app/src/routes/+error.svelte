<script>
	import { page } from '$app/stores';
</script>

<h1>{$page.status}: {$page.error.message}</h1>
<div>
	Something went wrong. The route <tt>{new URL($page.url).pathname}</tt> does not exist in this application.
</div>
