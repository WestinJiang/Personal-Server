<script>
	import { Form, FormGroup, Label, Input, Button, ButtonToolbar } from 'sveltestrap';
	import { Alert } from 'sveltestrap';
	let username = 'da user';
	let password = 'thepassword';
	export let onSubmit;
	export let autherror;
	function handleSubmit(event) {
		event.preventDefault();
		onSubmit && onSubmit({ username, password });
		return false;
	}
</script>

<Form method="POST" on:submit={handleSubmit}>
	<FormGroup>
		<Label for="username">Username</Label>
		<Input type="text" name="username" id="username" bind:value={username} />
	</FormGroup>
	<FormGroup>
		<Label for="password">Password</Label>
		<Input type="password" name="password" id="password" bind:value={password} />
	</FormGroup>
	{#if autherror}
		<FormGroup>
			<Alert color="danger" role="alert">
				{autherror}
			</Alert>
		</FormGroup>
	{/if}
	<ButtonToolbar>
		<Button color="primary" type="submit" class="me-1">Login</Button>
		<Button color="secondary" type="reset">Reset</Button>
	</ButtonToolbar>
</Form>
