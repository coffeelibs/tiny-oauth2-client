package io.coffeelibs.tinyoauth2client;

import io.coffeelibs.tinyoauth2client.http.RedirectTarget;
import io.coffeelibs.tinyoauth2client.util.RandomUtil;
import org.jetbrains.annotations.Blocking;
import org.jetbrains.annotations.VisibleForTesting;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Simple OAuth 2.0 Authentication Code Flow with {@link PKCE}.
 * <p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8252">RFC 8252</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7636">RFC 7636</a>
 */
public class AuthFlow {

	@VisibleForTesting
	final String clientId;
	@VisibleForTesting
	final PKCE pkce;

	private AuthFlow(String clientId) {
		this.clientId = clientId;
		this.pkce = new PKCE();
	}

	/**
	 * Initializes a new Authentication Code Flow for the given {@code clientId}
	 *
	 * @param clientId Public <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.2">Client Identifier</a>
	 * @return A new Authentication Flow
	 */
	public static AuthFlow asClient(String clientId) {
		return new AuthFlow(clientId);
	}

	/**
	 * Asks the given {@code browser} to browse the authorization URI. This method will block until the browser is
	 * <a href="https://datatracker.ietf.org/doc/html/rfc8252#section-4.1">redirected back to this application</a>.
	 *
	 * @param authEndpoint The URI of the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.1">Authorization Endpoint</a>
	 * @param browser      An async callback that opens a web browser with the URI it consumes
	 * @param scopes       The desired <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
	 * @return The authentication flow that is now in possession of an authorization code
	 * @throws IOException In case of I/O errors during communication between browser and this application
	 * @see #authorize(URI, Consumer, Set, String, int...)
	 */
	public AuthFlowWithCode authorize(URI authEndpoint, Consumer<URI> browser, String... scopes) throws IOException {
		return authorize(authEndpoint, browser, Set.of(scopes), "/" + RandomUtil.randomToken(16));
	}

	/**
	 * Asks the given {@code browser} to browse the authorization URI. This method will block until the browser is
	 * <a href="https://datatracker.ietf.org/doc/html/rfc8252#section-4.1">redirected back to this application</a>.
	 *
	 * @param authEndpoint The URI of the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.1">Authorization Endpoint</a>
	 * @param browser      An async callback that opens a web browser with the URI it consumes
	 * @param scopes       The desired access token <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
	 * @param path         The path to use in the redirect URI
	 * @param ports        TCP port(s) to attempt to bind to and use in the loopback redirect URI
	 * @return The authentication flow that is now in possession of an authorization code
	 * @throws IOException In case of I/O errors during communication between browser and this application
	 */
	@Blocking
	public AuthFlowWithCode authorize(URI authEndpoint, Consumer<URI> browser, Set<String> scopes, String path, int... ports) throws IOException {
		try (var redirectTarget = RedirectTarget.start(path, ports)) {
			var encodedRedirectUri = URLEncoder.encode(redirectTarget.getRedirectUri().toASCIIString(), StandardCharsets.US_ASCII);

			// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
			StringBuilder queryString = new StringBuilder();
			if (authEndpoint.getRawQuery() != null) {
				queryString.append(authEndpoint.getRawQuery());
				queryString.append('&');
			}
			queryString.append("response_type=code");
			queryString.append("&client_id=").append(clientId);
			queryString.append("&state=").append(redirectTarget.getCsrfToken());
			queryString.append("&code_challenge=").append(pkce.challenge);
			queryString.append("&code_challenge_method=").append(PKCE.METHOD);
			queryString.append("&redirect_uri=").append(encodedRedirectUri);
			if (!scopes.isEmpty()) {
				queryString.append("&scope=");
				queryString.append(scopes.stream().map(s -> URLEncoder.encode(s, StandardCharsets.US_ASCII)).collect(Collectors.joining("+")));
			}

			var authUri = URI.create(authEndpoint.getScheme() + "://" + authEndpoint.getRawAuthority() + authEndpoint.getRawPath() + "?" + queryString);
			ForkJoinPool.commonPool().execute(() -> browser.accept(authUri));
			var code = redirectTarget.receive();
			return new AuthFlowWithCode(encodedRedirectUri, code);
		}
	}

	/**
	 * The successfully authenticated authentication flow, ready to retrieve an access token.
	 */
	public class AuthFlowWithCode {
		private String encodedRedirectUri;
		private String authorizationCode;

		@VisibleForTesting
		AuthFlowWithCode(String encodedRedirectUri, String authorizationCode) {
			this.encodedRedirectUri = encodedRedirectUri;
			this.authorizationCode = authorizationCode;
		}

		/**
		 * Requests a access/refresh token from the given {@code tokenEndpoint}.
		 *
		 * @param tokenEndpoint The URI of the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.2">Token Endpoint</a>
		 * @return The raw <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
		 * @throws IOException          In case of I/O errors when communicating with the token endpoint
		 * @throws InterruptedException When this thread is interrupted before a response is received
		 */
		@Blocking
		public String getAccessToken(URI tokenEndpoint) throws IOException, InterruptedException {
			// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
			StringBuilder requestBody = new StringBuilder();
			requestBody.append("grant_type=authorization_code");
			requestBody.append("&client_id=").append(clientId);
			requestBody.append("&code_verifier=").append(pkce.verifier);
			requestBody.append("&code=").append(authorizationCode);
			requestBody.append("&redirect_uri=").append(encodedRedirectUri);
			var request = HttpRequest.newBuilder(tokenEndpoint) //
					.header("Content-Type", "application/x-www-form-urlencoded") //
					.POST(HttpRequest.BodyPublishers.ofString(requestBody.toString())) //
					.build();
			HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() == 200) {
				return response.body();
			} else {
				throw new IOException("Unexpected HTTP response code " + response.statusCode());
			}
		}


	}

}
