<script>
	import { SvelteToast } from '@zerodevx/svelte-toast';
	import { invalidateAll } from '$app/navigation';
	import { Nav, Collapse, Navbar, NavbarToggler, NavItem, NavLink, NavbarBrand } from 'sveltestrap';
	import DropDowns from '$lib/dropdown.svelte';
	import { menus, branding } from '$lib/config';
	import { user } from '$lib/userstore';

	const toastoptions = {
		pausable: true
	};
	let navbarOpen = false;
</script>

<SvelteToast options={toastoptions} />
<svelte:head>
	<link href="css/bootswatch-simplex.min.css" rel="stylesheet" type="text/css" />
</svelte:head>
<svelte:window on:visibilitychange={() => window.visibilityState === 'visible'
										  && invalidateAll} />

<div>
	<Navbar color="light" light expand="md">
		<NavbarToggler on:click={() => (navbarOpen = !navbarOpen)} />
		<NavbarBrand to="/">{branding}</NavbarBrand>
		<Collapse
			isOpen={navbarOpen}
			expand="md"
			on:update={(event) => (navbarOpen = event.detail.isOpen)}
			navbar
		>
			<Nav class="mr-auto" navbar>
				{#each menus.topbar as item (item.path)}
					<NavItem>
						<NavLink href={item.path}>
							{item.label}
						</NavLink>
					</NavItem>
				{/each}
				{#if menus.leftdropdowns.length > 0}
					<DropDowns dropdowns={menus.leftdropdowns} />
				{/if}
			</Nav>
			<Nav class="ml-auto" navbar>
				<DropDowns dropdowns={menus.rightdropdowns} />
				{#if $user}
					<NavItem>
						<NavLink href="/logout">Logout ({$user.sub})</NavLink>
					</NavItem>
				{:else}
					<NavItem>
						<NavLink href="/login">Login</NavLink>
					</NavItem>
				{/if}
			</Nav>
		</Collapse>
	</Navbar>
	<div class="container-fluid marketing">
		<slot />
	</div>
</div>

<style>
	:root {
		--toastWidth: auto;
		--toastBorder: 2px solid #444;
		--toastContainerTop: auto;
		--toastContainerRight: 2rem;
		--toastContainerBottom: 2rem;
		--toastContainerLeft: auto;
	}
</style>