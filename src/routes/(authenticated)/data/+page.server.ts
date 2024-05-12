export const prerender = true;

export async function load({ fetch }) {
    const response = await fetch('https://oj.dcs.upd.edu.ph/api/v2/submissions');
	const results = await response.json();
	const data: Array = results.data.objects;

    return { results: data }
}