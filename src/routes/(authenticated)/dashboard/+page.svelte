<script lang="ts">
	import type { PageData } from "./$types";
	
	export let data: PageData;
	
</script>

<section class="prose mx-auto justify-center">
	<h1>Dashboard</h1>
	<p>🎉 Hello there <strong>{data.user?.username}</strong>, you're logged in!</p>
	<ul>
		<li><a href="/data" data-sveltekit-preload-data>Data</a> OJ Submissions</li>
		<li>
			<a href="/logout" class="link" data-sveltekit-reload>Log Out</a>
		</li>
	</ul>
</section>
