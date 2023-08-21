import crypto from 'node:crypto';
import process from 'node:process';
import cookieParser from 'cookie-parser';
import express from 'express';
import dotenv from 'dotenv';
import {getClient, getFetchError} from '@discord/auth';

dotenv.config();

const app = express();
app.use(cookieParser(process.env.COOKIE_SECRET));

const client = getClient({
	clientId: process.env.DISCORD_CLIENT_ID,
	clientSecret: process.env.DISCORD_CLIENT_SECRET,
	redirectUri: process.env.DISCORD_REDIRECT_URI,
});

app.get('/auth', async (request, response) => {
	const state = crypto.randomUUID();

	// Store the signed state param in the user's cookies so we can verify
	// the value later. See:
	// https://discord.com/developers/docs/topics/oauth2#state-and-security
	response.cookie('clientState', state, {maxAge: 1000 * 60 * 5, signed: true});

	const url = await client.getOAuthUrl({
		state,
		scopes: ['identify'],
	});

	// Send the user to the Discord owned OAuth2 authorization endpoint
	response.redirect(url);
});

/**
 * Route configured in the Discord developer console, the redirect Url to which
 * the user is sent after approving the bot for their Discord account. This
 * completes a few steps:
 * 1. Uses the code to acquire Discord OAuth2 tokens
 * 2. Uses the Discord Access Token to fetch the user profile
 * 3. Stores the OAuth2 Discord Tokens in Redis / Firestore
 * 4. Generates an OAuth2 consent dialog url for Fitbit, and redirects the user.
 */
app.get('/oauth2-redirect', async (request, response) => {
	try {
		// 1. Uses the code and state to acquire Discord OAuth2 tokens
		const code = request.query.code;
		const discordState = request.query.state;

		// Make sure the state parameter exists
		const {clientState} = request.signedCookies;
		if (clientState !== discordState) {
			console.error('State verification failed.');
			return response.sendStatus(403);
		}

		const tokens = await client.getOAuthTokens(code);
		console.log(tokens);

		const url = 'https://discord.com/api/v10/users/@me';
		const result = await fetch(url, {
			headers: {
				authorization: `Bearer ${tokens.access_token}`,
			},
		});
		if (!result.ok) {
			const error = await getFetchError(result);
			throw error;
		}

		const profile = await result.json();
		response.send(JSON.stringify(profile, null, 2));
	} catch (error) {
		console.error(error);
		response.sendStatus(500);
	}
});

/**
 * Given a token and optional token_type_hint, revoke the given token
 */
app.get('/revoke', async (request, response) => {
	const {token, token_type_hint} = request.query;
	await client.revokeToken({
		token,
		token_type_hint,
	});
	response.send('👍');
});

/**
 * Given an access token, fetch the user's profile.
 */
app.get('/profile', async (request, response) => {
	const access_token = request.query.access_token;
	const url = 'https://discord.com/api/v10/users/@me';
	const result = await fetch(url, {
		headers: {
			authorization: `Bearer ${access_token}`,
		},
	});
	if (!result.ok) {
		const error = await getFetchError(result);
		throw error;
	}

	const profile = await result.json();
	response.send(JSON.stringify(profile, null, 2));
});

/**
 * Start up the web server
 */
app.listen(3000, () => {
	console.log(`App listening at http://localhost:3000`);
});
