package io.github.coffeelibs.tinyoauth2client;

import io.github.coffeelibs.tinyoauth2client.util.URIUtil;
import org.jetbrains.annotations.Blocking;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Objects;

/**
 * An OAuth2 <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.1">public client</a> capable of making requests to a token endpoint.
 * 
 * @see TinyOAuth2#client(String)
 */
public class TinyOAuth2Client {

	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.2">Client Identifier</a>
	 */
	final String clientId;

	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.2">Token Endpoint</a>
	 */
	final URI tokenEndpoint;

	TinyOAuth2Client(String clientId, URI tokenEndpoint) {
		this.clientId = Objects.requireNonNull(clientId);
		this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint);
	}

	/**
	 * Initializes a new Authentication Code Flow with <a href="https://datatracker.ietf.org/doc/html/rfc7636">PKCE</a>
	 *
	 * @param authEndpoint The URI of the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.1">Authorization Endpoint</a>
	 * @return A new Authentication Flow
	 */
	public AuthFlow authFlow(URI authEndpoint) {
		return new AuthFlow(this, authEndpoint, new PKCE());
	}

	/**
	 * Refreshes an access token using the given {@code refreshToken}.
	 *
	 * @param refreshToken The refresh token
	 * @param scopes       The desired access token <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
	 * @return The raw <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
	 * @throws IOException          In case of I/O errors when communicating with the token endpoint
	 * @throws InterruptedException When this thread is interrupted before a response is received
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-6">RFC 6749 Section 6: Refreshing an Access Token</a>
	 */
	@Blocking
	public String refresh(String refreshToken, String... scopes) throws IOException, InterruptedException {
		var requestBody = URIUtil.buildQueryString(Map.of(//
				"grant_type", "refresh_token", //
				"refresh_token", refreshToken, //
				"client_id", clientId, //
				"scope", String.join(" ", scopes)
		));
		var request = HttpRequest.newBuilder(tokenEndpoint) //
				.header("Content-Type", "application/x-www-form-urlencoded") //
				.POST(HttpRequest.BodyPublishers.ofString(requestBody)) //
				.build();
		HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() == 200) {
			return response.body();
		} else {
			throw new IOException("Unexpected HTTP response code " + response.statusCode());
		}
	}

}
