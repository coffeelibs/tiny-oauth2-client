package io.github.coffeelibs.tinyoauth2client;

import java.net.URI;

/**
 * Fluent builder for a {@link TinyOAuth2Client}
 */
public class TinyOAuth2 {

	private TinyOAuth2() {
	}

	/**
	 * Begins building a new Tiny OAuth2 Client
	 * @param clientId Public <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.2">Client Identifier</a>
	 * @return A new {@link TinyOAuth2Client} Builder
	 */
	public static TinyOAuth2ClientWithoutTokenEndpoint client(String clientId) {
		return tokenEndpoint -> new TinyOAuth2Client(clientId, tokenEndpoint);
	}

	public interface TinyOAuth2ClientWithoutTokenEndpoint {

		/**
		 * @param tokenEndpoint The URI of the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.2">Token Endpoint</a>
		 * @return A new client
		 */
		TinyOAuth2Client withTokenEndpoint(URI tokenEndpoint);
	}
}
