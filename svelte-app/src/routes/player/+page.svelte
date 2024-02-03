<script>
	import { Col, Container, Row } from 'sveltestrap';
	import { Form, FormGroup, Label, Button, ButtonToolbar } from 'sveltestrap';
	import {
		Input,
		Spinner,
		Dropdown,
		DropdownToggle,
		DropdownMenu,
		DropdownItem
	} from 'sveltestrap';
	import VideoPlayer from 'svelte-video-player';

	function handleSubmit(event) {
		event.preventDefault();
		playUrl = inputUrl;
		const videoElement = player.querySelectorAll('video')[0];
		videoElement.load();
		videoElement.play();
		return false;
	}
	let isOpen = false;
	let playUrl = '';
	let inputUrl = 'https://sveltejs.github.io/assets/caminandes-llamigos.mp4';
	let player;

	function updatePlayer() {
		inputUrl = playUrl;
	}
	$: playUrl && updatePlayer();
	export let data;
</script>

<Container>
	<Row class="mt-2">
		<h1>Welcome to the Player page</h1>
	</Row>
	<Row class="mt-2">
		<Form on:submit={handleSubmit}>
			<Container>
				<Row>
					<Col>
						<FormGroup>
							<Label for="url">Enter URL</Label>
							<Input type="text" name="url" bind:value={inputUrl} />
						</FormGroup>
						<ButtonToolbar>
							<Button type="submit" color="success" class="mr-2">Play</Button>
						</ButtonToolbar>
					</Col>
					<Col>
						<FormGroup>
							<Label for="ddmenu">or select one from the list of</Label>
							{#await data.videos}
								<Spinner size="lg" color="primary" />
							{:then videos}
								<Dropdown {isOpen} toggle={() => (isOpen = !isOpen)}>
									<DropdownToggle caret>Available MP4s</DropdownToggle>
									<DropdownMenu>
										{#each videos as v (v.name)}
											<DropdownItem on:click={() => (playUrl = v.name)}>
												{v.name}
											</DropdownItem>
										{/each}
									</DropdownMenu>
								</Dropdown>
							{/await}
						</FormGroup>
					</Col>
				</Row>
			</Container>
		</Form>
	</Row>
	<Row class="mt-3">
		<Col>
			<p>
				If your implementation of range byte requests works, you should be able to stream MP4 from
				your server.
			</p>
			<p>Currently playing <tt>{playUrl}</tt></p>
			<div style="max-width: 800px; margin: 0 auto;" bind:this={player}>
				<VideoPlayer source={playUrl} />
			</div>
		</Col>
	</Row>
</Container>
