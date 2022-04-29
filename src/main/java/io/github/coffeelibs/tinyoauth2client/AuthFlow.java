package io.github.coffeelibs.tinyoauth2client;

import io.github.coffeelibs.tinyoauth2client.http.RedirectTarget;
import io.github.coffeelibs.tinyoauth2client.http.Response;
import io.github.coffeelibs.tinyoauth2client.util.RandomUtil;
import io.github.coffeelibs.tinyoauth2client.util.URIUtil;
import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.Blocking;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.VisibleForTesting;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Consumer;

/**
 * Simple OAuth 2.0 Authentication Code Flow with {@link PKCE}.
 *
 * @see TinyOAuth2Client#authFlow(URI)
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8252">RFC 8252</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7636">RFC 7636</a>
 */
@ApiStatus.Experimental
public class AuthFlow {

	/**
	 * Use a system-assigned port number
	 */
	public static int[] SYSTEM_ASSIGNED_PORT = {0};

	@VisibleForTesting
	final TinyOAuth2Client client;
	@VisibleForTesting
	final URI authEndpoint;
	@VisibleForTesting
	final PKCE pkce;

	@VisibleForTesting
	String redirectPath = "/" + RandomUtil.randomToken(16);
	@VisibleForTesting
	int[] redirectPorts = SYSTEM_ASSIGNED_PORT;
	@VisibleForTesting
	Response successResponse = Response.html(Response.Status.OK, "<html><body>Success</body></html>");
	@VisibleForTesting
	Response errorResponse = Response.html(Response.Status.OK, "<html><body>Error</body></html>");

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
	 * Sets the path, which this app will listen to and which will be used in the {@code redirect_uri}.
	 * <p>
	 * Defaults to a random path, which may not be supported by all Authorization Servers.
	 *
	 * @param path Path component of the URI used as <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2">Redirection Endpoint</a>
	 * @return this
	 */
	@Contract("!null -> this")
	public AuthFlow setRedirectPath(String path) {
		if (!path.startsWith("/")) {
			throw new IllegalArgumentException("Path should be absolute");
		}
		this.redirectPath = path;
		return this;
	}

	/**
	 * Sets the port number, which this app will listen on and which will be used in the {@code redirect_uri}.
	 * <p>
	 * Defaults to an unpredictable {@link #SYSTEM_ASSIGNED_PORT}, which may not be supported by all Authorization Servers.
	 *
	 * @param ports One or many TCP port(s) in to attempt to bind to and use in the loopback redirect URI.
	 *              If multiple ports are defined, they will be used as fallbacks in case the preceding port is
	 *              already bound.
	 * @return this
	 */
	@Contract("!null -> this")
	public AuthFlow setRedirectPort(int... ports) {
		this.redirectPorts = Objects.requireNonNull(ports);
		return this;
	}

	/**
	 * Asks the given {@code browser} to browse the authorization URI. This method will block until the browser is
	 * <a href="https://datatracker.ietf.org/doc/html/rfc8252#section-4.1">redirected back to this application</a>.
	 *
	 * @param browser An async callback that opens a web browser with the URI it consumes
	 * @param scopes  The desired <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
	 * @return The authentication flow that is now in possession of an authorization code
	 * @throws IOException In case of I/O errors during communication between browser and this application
	 */
	@Blocking
	public AuthFlowWithCode authorize(Consumer<URI> browser, String... scopes) throws IOException {
		try (var redirectTarget = RedirectTarget.start(redirectPath, redirectPorts)) {
			redirectTarget.setSuccessResponse(successResponse);
			redirectTarget.setErrorResponse(errorResponse);
			var redirectUri = redirectTarget.getRedirectUri().toASCIIString();

			String queryString = "";
			if (authEndpoint.getRawQuery() != null) {
				// query component [...] MUST be retained when adding additional query parameters
				// as per https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
				queryString = authEndpoint.getRawQuery() + "&";
			}
			queryString += URIUtil.buildQueryString(Map.of( //
					"response_type", "code", //
					"client_id", client.clientId, //
					"state", redirectTarget.getCsrfToken(), //
					"code_challenge", pkce.challenge, //
					"code_challenge_method", PKCE.METHOD, //
					"redirect_uri", redirectTarget.getRedirectUri().toASCIIString(), //
					"scope", String.join(" ", scopes)
			));

			var authUri = URI.create(authEndpoint.getScheme() + "://" + authEndpoint.getRawAuthority() + authEndpoint.getRawPath() + "?" + queryString);
			ForkJoinPool.commonPool().execute(() -> browser.accept(authUri));
			var code = redirectTarget.receive();
			return new AuthFlowWithCode(redirectUri, code);
		}
	}

	/**
	 * The successfully authenticated authentication flow, ready to retrieve an access token.
	 */
	public class AuthFlowWithCode {
		private final String redirectUri;
		private final String authorizationCode;

		@VisibleForTesting
		AuthFlowWithCode(String redirectUri, String authorizationCode) {
			this.redirectUri = redirectUri;
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
			var requestBody = URIUtil.buildQueryString(Map.of( //
					"grant_type", "authorization_code", //
					"client_id", client.clientId, //
					"code_verifier", pkce.verifier, //
					"code", authorizationCode, //
					"redirect_uri", redirectUri //
			));
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
