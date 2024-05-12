import { auth } from "$lib/auth";
import type { Handle } from "@sveltejs/kit";

export const handle: Handle = async ({ event, resolve }) => {
	const token = event.cookies.get("auth_token") as string;

	if (token) {
		const resp = await auth.validate_session({
			token,
			opts: { cookies: event.cookies },
		});

		if (resp.isOk()) {
			event.locals.user = resp.value;
		} else {

			console.error("Error validating session:", resp.error);
		}
	}

	return resolve(event);
};

export function handleError() {
	return {
		message: 'Kaboom!'
	};
}