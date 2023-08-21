/**
 * The following methods all facilitate OAuth2 communication with Discord.
 * See https://discord.com/developers/docs/topics/oauth2 for more details.
 */

export type OAuth2TokenResponse = {
	access_token: string;
	expires_in: number;
	expires_at: number;
	refresh_token: string;
	scope: string;
	token_type: string;
};

export type ClientCredentialsGrantResponse = Omit<
	OAuth2TokenResponse,
	'token_type'
>;

export type OAuth2UserInfo = {
	application: {
		id: string;
		name: string;
		icon: string | undefined;
		description: string;
		summary: string;
		type: string | undefined;
		hook: boolean;
		bot_public: boolean;
		bot_require_code_grant: boolean;
		verify_key: string;
		flags: number;
	};
	scopes: string[];
	expires: string;
	user: {
		id: string;
		username: string;
		avatar: string;
		avatar_decoration: string | undefined;
		discriminator: string;
		public_flags: number;
	};
};

export type GetOAuthUrlOptions = {
	state: string;
	scopes: string | string[];
	prompt?: 'consent' | 'none';
	responseType?: 'code' | 'token';
};

export type AuthClientOptions = {
	clientId: string;
	clientSecret: string;
	redirectUri: string;
};

type GetTokenOptions = {
	grant_type: 'client_credentials' | 'authorization_code' | 'refresh_token';
	code?: string;
	refresh_token?: string;
};

export type RevokeTokenOptions = {
	token: string;
	token_type_hint?: 'refresh_token' | 'access_token';
};

export class AuthClient {
	clientId: string;
	clientSecret: string;
	redirectUri: string;
	constructor(options: AuthClientOptions) {
		if (!options.clientId) {
			throw new Error('clientId is required.');
		}

		this.clientId = options.clientId;

		if (!options.clientSecret) {
			throw new Error('clientSecret is required.');
		}

		this.clientSecret = options.clientSecret;

		if (!options.redirectUri) {
			throw new Error('redirectUri is required.');
		}

		this.redirectUri = options.redirectUri;
	}

	/**
	 * Generate the url which the user will be directed to in order to approve the
	 * bot, and see the list of requested scopes.
	 */
	async getOAuthUrl(options: GetOAuthUrlOptions) {
		const url = new URL('https://discord.com/api/oauth2/authorize');
		const scope = Array.isArray(options.scopes)
			? options.scopes.join(' ')
			: options.scopes;
		url.searchParams.set('client_id', this.clientId);
		url.searchParams.set('redirect_uri', this.redirectUri);
		url.searchParams.set('response_type', options.responseType ?? 'code');
		url.searchParams.set('state', options.state);
		url.searchParams.set('scope', scope);
		url.searchParams.set('prompt', options.prompt ?? 'consent');
		return url.toString();
	}

	/**
	 * Low level wrapper to obtain a set of tokens.
	 */
	async getToken(options: GetTokenOptions) {
		if (!options.grant_type) {
			throw new Error('grant_type is required.');
		}

		const url = 'https://discord.com/api/v10/oauth2/token';
		const data = new URLSearchParams({
			client_id: this.clientId,
			client_secret: this.clientSecret,
			grant_type: options.grant_type,
			redirect_uri: this.redirectUri,
		});
		if (options.code) {
			data.append('code', options.code);
		}

		if (options.refresh_token) {
			data.append('refresh_token', options.refresh_token);
		}

		const result = await request<OAuth2TokenResponse>(url, {
			body: data,
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
		});
		result.expires_at = Date.now() + result.expires_in * 1000;
		return result;
	}

	/**
	 * Given an OAuth2 code from the scope approval page, make a request to Discord's
	 * OAuth2 service to retreive an access token, refresh token, and expiration.
	 */
	async getOAuthTokens(code: string): Promise<OAuth2TokenResponse> {
		const token = await this.getToken({
			grant_type: 'authorization_code',
			code,
		});
		return token;
	}

	/**
	 * Obtain a new access token, but only if the current one is expired.
	 */
	async getRefreshedTokenIfExpired(
		tokens: OAuth2TokenResponse,
	): Promise<OAuth2TokenResponse> {
		if (Date.now() > tokens.expires_at) {
			const result = await this.refreshToken(tokens.refresh_token);
			return result;
		}

		return tokens;
	}

	/**
	 * The initial token request comes with both an access token and a refresh
	 * token.  Check if the access token has expired, and if it has, use the
	 * refresh token to acquire a new, fresh access token.
	 */
	async refreshToken(refreshToken: string): Promise<OAuth2TokenResponse> {
		const token = await this.getToken({
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
		});
		return token;
	}

	/**
	 * Revoke the given user's Discord access and refresh tokens.
	 * @param userId The Discord User ID
	 */
	async revokeToken(options: RevokeTokenOptions) {
		const url = 'https://discord.com/api/oauth2/token/revoke';

		const body = new URLSearchParams({
			client_id: this.clientId,
			client_secret: this.clientSecret,
			token: options.token,
		});
		if (options.token_type_hint) {
			body.append('token_type_hint', options.token_type_hint);
		}

		console.log(body);

		// Revoke the refresh token
		const response = await request<unknown>(url, {
			method: 'POST',
			body,
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
		});

		console.log(response);
	}

	/**
	 * Given a user based access token, fetch profile information for the current user.
	 */
	async getUserData(tokens: OAuth2TokenResponse) {
		const url = 'https://discord.com/api/v10/oauth2/@me';
		const result = await request<OAuth2UserInfo>(url, {
			headers: {
				Authorization: `Bearer ${tokens.access_token}`,
			},
		});
		return result;
	}
}

export async function request<T>(
	url: string,
	options: RequestInit = {},
): Promise<T> {
	const result = await fetch(url, options);
	console.log(`[${result.status}] ${url}`);
	if (result.ok) {
		if (result.headers.get('content-type')?.includes('application/json')) {
			const json = (await result.json()) as T;
			return json;
		}

		const text = await result.text();
		return text as T;
	}

	const error = await getFetchError(result);
	throw error;
}

export async function getFetchError(response: Response): Promise<FetchError> {
	let errorText = `Error fetching ${response.url}: ${response.status} ${response.statusText}`;
	try {
		const error = await response.text();
		if (error) {
			errorText = `${errorText} \n\n ${error}`;
		}
	} catch {
		// ignore
	}

	console.error(errorText);
	return new FetchError(errorText, response);
}

export class FetchError extends Error {
	constructor(
		message: string,
		public response: Response,
	) {
		super(message);
	}
}

export function getClient(options: AuthClientOptions) {
	return new AuthClient(options);
}
