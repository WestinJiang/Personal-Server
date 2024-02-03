<script>
	import { user } from '$lib/userstore';
	import { NavLink, Dropdown, DropdownToggle, DropdownMenu, DropdownItem } from 'sveltestrap';
	export let dropdowns;
	function shouldShow(dropdown, user) {
		if (!dropdown.onlyifauthenticated) return true;
		return Boolean(user);
	}
</script>

{#each dropdowns as dropdown}
	{#if shouldShow(dropdown, $user)}
		<Dropdown nav inNavbar>
			<DropdownToggle nav caret>{dropdown.label}</DropdownToggle>
			<DropdownMenu end>
				{#each dropdown.entries as entry}
					<DropdownItem>
						<NavLink href={entry.path}>
							{entry.label}
						</NavLink>
					</DropdownItem>
				{/each}
			</DropdownMenu>
		</Dropdown>
	{/if}
{/each}
