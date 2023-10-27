package io.github.coffeelibs.tinyoauth2client;

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.Blocking;
import org.jetbrains.annotations.NonBlocking;
import org.jetbrains.annotations.VisibleForTesting;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * Simple OAuth 2.0 Client Credentials Grant
 *
 * @see TinyOAuth2Client#clientCredentialsGrant(Charset, CharSequence) ()
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.4">RFC 6749, Section 4.4</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1">RFC 6749, Section 3.2.1</a>
 */
@ApiStatus.Experimental
public class ClientCredentialsGrant {

	@VisibleForTesting
	final TinyOAuth2Client client;

	@VisibleForTesting
	final String basicAuthHeader;

	ClientCredentialsGrant(TinyOAuth2Client client, Charset charset, CharSequence clientSecret) {
		this.client = client;
		this.basicAuthHeader = buildBasicAuthHeader(charset, client.clientId, clientSecret);
	}

	/**
	 * Requests a new access token, using the pre-shared client credentials to authenticate against the authorization server.
	 *
	 * @param httpClient The http client used to recieve the authorization code
	 * @param scopes     The desired <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
	 * @return The <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
	 * @throws IOException          In case of I/O errors when communicating with the token endpoint
	 * @throws InterruptedException When this thread is interrupted before a response is received
	 * @see #authorizeAsync(HttpClient, String...)
	 */
	@Blocking
	public HttpResponse<String> authorize(HttpClient httpClient, String... scopes) throws IOException, InterruptedException {
		var req = buildTokenRequest(Set.of(scopes));
		return httpClient.send(req, HttpResponse.BodyHandlers.ofString());
	}

	/**
	 * Requests a new access token, using the pre-shared client credentials to authenticate against the authorization server.
	 *
	 * @param httpClient The http client used to recieve the authorization code
	 * @param scopes     The desired <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
	 * @return The future <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
	 * @see #authorize(HttpClient, String...)
	 */
	@NonBlocking
	public CompletableFuture<HttpResponse<String>> authorizeAsync(HttpClient httpClient, String... scopes) {
		var req = buildTokenRequest(Set.of(scopes));
		return httpClient.sendAsync(req, HttpResponse.BodyHandlers.ofString());
	}

	@VisibleForTesting
	static String buildBasicAuthHeader(Charset charset, String clientId, CharSequence clientSecret) {
		// while it is inevitable to have a String copy of the encoded header in memory during the http request,
		// this is an attempt to at least avoid unnecessary copies of the clientSecret:
		var userPassChars = CharBuffer.allocate(clientId.length() + 1 + clientSecret.length());
		userPassChars.put(clientId).put(':').put(CharBuffer.wrap(clientSecret)).flip();
		var userPassBytes = charset.encode(userPassChars);
		var base64Bytes = Base64.getEncoder().encode(userPassBytes);
		try {
			return "Basic " + StandardCharsets.US_ASCII.decode(base64Bytes);
		} finally {
			Arrays.fill(userPassChars.array(), ' ');
			Arrays.fill(userPassBytes.array(), (byte) 0x00);
			Arrays.fill(base64Bytes.array(), (byte) 0x00);
		}
	}

	@VisibleForTesting
	HttpRequest buildTokenRequest(Collection<String> scopes) {
		var params = scopes.isEmpty()
				? Map.of("grant_type", "client_credentials")
				: Map.of("grant_type", "client_credentials", "scope", String.join(" ", scopes));
		var req = client.createTokenRequest(params);

		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1:
		// The authorization server MUST support the HTTP Basic authentication [...]
		// Alternatively, the authorization server MAY support including the client credentials in the request-body [...]
		// Including the client credentials in the request-body using the two parameters is NOT RECOMMENDED and
		// SHOULD be limited to clients unable to directly utilize the HTTP Basic authentication scheme
		req.setHeader("Authorization", basicAuthHeader);
		return req.build();
	}

}
