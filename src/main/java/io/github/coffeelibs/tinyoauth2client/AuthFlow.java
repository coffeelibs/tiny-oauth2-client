package io.github.coffeelibs.tinyoauth2client;

import io.github.coffeelibs.tinyoauth2client.http.RedirectTarget;
import io.github.coffeelibs.tinyoauth2client.http.Response;
import io.github.coffeelibs.tinyoauth2client.util.RandomUtil;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.Blocking;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.VisibleForTesting;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Simple OAuth 2.0 Authentication Code Flow with {@link PKCE}.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8252">RFC 8252</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7636">RFC 7636</a>
 */
@ApiStatus.Experimental
public class AuthFlow {


	@VisibleForTesting
	final TinyOAuth2Client client;
	@VisibleForTesting
	final URI authEndpoint;
	@VisibleForTesting
	final PKCE pkce;

	private Response successResponse;
	private Response errorResponse;

	AuthFlow(TinyOAuth2Client client, URI authEndpoint, PKCE pkce) {
		this.client = Objects.requireNonNull(client);
		this.authEndpoint = Objects.requireNonNull(authEndpoint);
		this.pkce = Objects.requireNonNull(pkce);
	}

	/**
	 * HTML to display in the Resource Owner's user agent after successful authorization.
	 *
	 * @param html content served with {@code Content-Type: text/html; charset=UTF-8}
	 * @return this
	 */
	@Contract("_ -> this")
	public AuthFlow withSuccessHtml(String html) {
		this.successResponse = Response.html(Response.Status.OK, html);
		return this;
	}

	/**
	 * Where to redirect the Resource Owner's user agent after successful authorization.
	 *
	 * @param target URI of page to show
	 * @return this
	 */
	@Contract("_ -> this")
	public AuthFlow withSuccessRedirect(URI target) {
		this.successResponse = Response.redirect(target);
		return this;
	}

	/**
	 * HTML to display in the Resource Owner's user agent after failed authorization.
	 *
	 * @param html content served with {@code Content-Type: text/html; charset=UTF-8}
	 * @return this
	 */
	@Contract("_ -> this")
	public AuthFlow withErrorHtml(String html) {
		this.errorResponse = Response.html(Response.Status.OK, html);
		return this;
	}

	/**
	 * Where to redirect the Resource Owner's user agent after failed authorization.
	 *
	 * @param target URI of page to show
	 * @return this
	 */
	@Contract("_ -> this")
	public AuthFlow withErrorRedirect(URI target) {
		this.errorResponse = Response.redirect(target);
		return this;
	}

	/**
	 * Asks the given {@code browser} to browse the authorization URI. This method will block until the browser is
	 * <a href="https://datatracker.ietf.org/doc/html/rfc8252#section-4.1">redirected back to this application</a>.
	 *
	 * @param browser      An async callback that opens a web browser with the URI it consumes
	 * @param scopes       The desired <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
	 * @return The authentication flow that is now in possession of an authorization code
	 * @throws IOException In case of I/O errors during communication between browser and this application
	 * @see #authorize(Consumer, Set, String, int...)
	 */
	@Blocking
	public AuthFlowWithCode authorize(Consumer<URI> browser, String... scopes) throws IOException {
		return authorize(browser, Set.of(scopes), "/" + RandomUtil.randomToken(16));
	}

	/**
	 * Asks the given {@code browser} to browse the authorization URI. This method will block until the browser is
	 * <a href="https://datatracker.ietf.org/doc/html/rfc8252#section-4.1">redirected back to this application</a>.
	 *
	 * @param browser      An async callback that opens a web browser with the URI it consumes
	 * @param scopes       The desired access token <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
	 * @param path         The path to use in the redirect URI
	 * @param ports        TCP port(s) to attempt to bind to and use in the loopback redirect URI
	 * @return The authentication flow that is now in possession of an authorization code
	 * @throws IOException In case of I/O errors during communication between browser and this application
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">RFC 6749 Section 4.1.1: Authorization Request</a>
	 */
	@Blocking
	public AuthFlowWithCode authorize(Consumer<URI> browser, Set<String> scopes, String path, int... ports) throws IOException {
		try (var redirectTarget = RedirectTarget.start(path, ports)) {
			if (successResponse != null) {
				redirectTarget.setSuccessResponse(successResponse);
			}
			if (errorResponse != null) {
				redirectTarget.setErrorResponse(errorResponse);
			}
			var encodedRedirectUri = URLEncoder.encode(redirectTarget.getRedirectUri().toASCIIString(), StandardCharsets.US_ASCII);

			StringBuilder queryString = new StringBuilder();
			if (authEndpoint.getRawQuery() != null) {
				queryString.append(authEndpoint.getRawQuery());
				queryString.append('&');
			}
			queryString.append("response_type=code");
			queryString.append("&client_id=").append(client.clientId);
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
		private final String encodedRedirectUri;
		private final String authorizationCode;

		@VisibleForTesting
		AuthFlowWithCode(String encodedRedirectUri, String authorizationCode) {
			this.encodedRedirectUri = encodedRedirectUri;
			this.authorizationCode = authorizationCode;
		}

		/**
		 * Requests a access/refresh token from the given {@code tokenEndpoint}.
		 *
		 * @return The raw <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
		 * @throws IOException          In case of I/O errors when communicating with the token endpoint
		 * @throws InterruptedException When this thread is interrupted before a response is received
		 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">RFC 6749 Section 4.1.3: Access Token Request</a>
		 */
		@Blocking
		public String getAccessToken() throws IOException, InterruptedException {
			StringBuilder requestBody = new StringBuilder();
			requestBody.append("grant_type=authorization_code");
			requestBody.append("&client_id=").append(client.clientId);
			requestBody.append("&code_verifier=").append(pkce.verifier);
			requestBody.append("&code=").append(authorizationCode);
			requestBody.append("&redirect_uri=").append(encodedRedirectUri);
			var request = HttpRequest.newBuilder(client.tokenEndpoint) //
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
