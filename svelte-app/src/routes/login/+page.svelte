<script>
	import { user } from '$lib/userstore';
	import { Container, Row, Col, Card, CardHeader, CardBody } from 'sveltestrap';
	import LoginForm from './loginform.svelte';
	import { goto } from '$app/navigation';
	import { success } from '$lib/toast.js';
	let autherror = undefined;
	async function doLogin(v) {
		const urlParams = new URLSearchParams(window.location.search);
		try {
			const r = await fetch('/api/login', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify(v)
			});
			if (r.ok) {
				const userobj = await r.json();
				success('Logged in as ' + userobj.sub);
				const dstpath = urlParams.get('next') || '/';
				console.log('login response json', userobj, 'going to', dstpath);
				user.login(userobj);
				goto(dstpath);
			} else {
				autherror = await r.text();
				console.log('login error', autherror);
			}
		} catch (er) {
			console.log('login error', er);
			autherror = String(er);
		}
	}
</script>

<Container>
	<Row class="pb-5 pt-5">
		<Col xs={{ size: 'auto', offset: 0 }} sm={{ size: 'auto', offset: 4 }}>
			<Card class="mx-auto">
				<CardHeader><h3>Please log in</h3></CardHeader>
				<CardBody>
					<LoginForm {autherror} onSubmit={(v) => doLogin(v)} />
				</CardBody>
			</Card>
		</Col>
	</Row>
</Container>
