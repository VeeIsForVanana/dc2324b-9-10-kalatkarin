import { err, ok } from 'neverthrow';
import { log } from 'debug';
import bcrypt from 'bcrypt';
import { createUser, getUsers, setToken } from '$lib/db';
import { seed_user } from './seed';

var attempts = 0;

export function attemptCounter(match) {
	if (!match){
		attempts += 1;
		if (attempts < 5){
			return err(new Error('mali'));
		}
		if (attempts == 5){
			attempts = 0;
			throw new Error("rebisco ka ba kasi sumosobra ka na")
		}
	}

	return;
}

export const cookie: AuthAdapter = {
	async validate_session({ token, opts }) {
		const [session_token] = token.split(':').slice(1);

		if (!opts?.cookies) return err(new Error('must pass cookies in to options'));
		if (!token) return err(new Error('No token provided'));

		const users = await getUsers();
		
		if (users.length === 0) await createUser(seed_user.username, seed_user.password);

		const user = users.find((user: User) => user.token === session_token);

		if (!user) return err(new Error('No user found'));

		return ok(user);
	},
	async login({ username, password, opts }) {
		if (!opts?.cookies) return err(new Error('Must pass cookies in to options'));
		if (!username) return err(new Error('Username is required'));
		if (!password) return err(new Error('Password is required'));

		const users = await getUsers();
		
		if (users.length === 0) await createUser(seed_user.username, seed_user.password);

		const user = users.find((u) => u.username === username);
		console.log(user);
		if (!user) return err(new Error('No user found'));
		const match = await bcrypt.compare(password, user.password);
		const attempt = attemptCounter(match);

		if(attempt) return attempt;

		user.token = generate_token();
		log('users:', users);

		setToken(user.token, user.id, username);

		return ok(user);
	},

	async signup({ username, password, password_confirm, opts }) {
		if (!opts?.cookies) return err(new Error('must pass cookies in to options'));
		if (!username) return err(new Error('username is required'));
		if (!password) return err(new Error('password is required'));
		if (password !== password_confirm) return err(new Error('passwords do not match'));

		await createUser(username, password);

		return ok();
	},

	async logout({ token, opts }) {
		if (!opts?.cookies) return err(new Error('must pass cookies into options'));
		opts.cookies.delete('auth_token', { path: '/' });

		return;
	}
};

function generate_token() {
	return Math.random().toString(36).slice(2);
}
