package io.github.coffeelibs.tinyoauth2client;

import io.github.coffeelibs.tinyoauth2client.util.URIUtil;
import org.jetbrains.annotations.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * An OAuth2 <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.1">public client</a> capable of making requests to a token endpoint.
 *
 * @see TinyOAuth2#client(String)
 */
@ApiStatus.Experimental
public class TinyOAuth2Client {

    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.2">Client Identifier</a>
     */
    final String clientId;

    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.2">Token Endpoint</a>
     */
    final URI tokenEndpoint;

    /**
     * Timeout of HTTP requests
     */
    final Duration requestTimeout;

    TinyOAuth2Client(String clientId, URI tokenEndpoint) {
        this(clientId, tokenEndpoint, DEFAULT_REQUEST_TIMEOUT);
    }

    private TinyOAuth2Client(String clientId, URI tokenEndpoint, Duration requestTimeout) {
        this.clientId = Objects.requireNonNull(clientId);
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint);
        this.requestTimeout = Objects.requireNonNull(requestTimeout);
    }

    /**
     * Creates a new OAuth2 Client with the specified request timeout
     * @param requestTimeout HTTP request timeout
     * @return A new client
     * @since 0.7.0
     */
    public TinyOAuth2Client withRequestTimeout(Duration requestTimeout) {
        return new TinyOAuth2Client(this.clientId, this.tokenEndpoint, requestTimeout);
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
     * Refreshes an access token using the given {@code refreshToken}. The request is made by the default http client returned by
     * {@link HttpClient#newHttpClient()} but on the given executor.
     *
     * @param executor     The executor to run the async tasks
     * @param refreshToken The refresh token
     * @param scopes       The desired access token <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
     * @return The future <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
     * @see #refresh(String, String...)
     */
    public CompletableFuture<HttpResponse<String>> refreshAsync(@BlockingExecutor Executor executor, String refreshToken, String... scopes) {
        return refreshAsync(HttpClient.newBuilder().executor(executor).build(), refreshToken, scopes);
    }

    /**
     * Refreshes an access token using the given {@code refreshToken}. The request is made by the given {@link HttpClient}.
     * <p>
     * The executor used to send the request and handle the response is the same specified in {@link HttpClient.Builder#executor(Executor)}
     *
     * @param httpClient   The http client used to send the request
     * @param refreshToken The refresh token
     * @param scopes       The desired access token <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
     * @return The future <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
     * @see #refresh(String, String...)
     */
    public CompletableFuture<HttpResponse<String>> refreshAsync(HttpClient httpClient, String refreshToken, String... scopes) {
        return httpClient.sendAsync(buildRefreshTokenRequest(refreshToken, scopes), HttpResponse.BodyHandlers.ofString()); //TODO
    }

    /**
     * Refreshes an access token using the given {@code refreshToken}. The request is made by the default http client returned by {@link HttpClient#newHttpClient()}.
     *
     * @param refreshToken The refresh token
     * @param scopes       The desired access token <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
     * @return The <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
     * @throws IOException          In case of I/O errors when communicating with the token endpoint
     * @throws InterruptedException When this thread is interrupted before a response is received
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-6">RFC 6749 Section 6: Refreshing an Access Token</a>
     * @see #refreshAsync(Executor, String, String...)
     */
    @Blocking
    public HttpResponse<String> refresh(String refreshToken, String... scopes) throws IOException, InterruptedException {
        return refresh(HttpClient.newHttpClient(), refreshToken, scopes);
    }

    /**
     * Refreshes an access token using the given {@code refreshToken}. The request is made by the given {@link HttpClient}.
     *
     * @param httpClient   The http client used to send the request
     * @param refreshToken The refresh token
     * @param scopes       The desired access token <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scopes</a>
     * @return The <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
     * @throws IOException          In case of I/O errors when communicating with the token endpoint
     * @throws InterruptedException When this thread is interrupted before a response is received
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-6">RFC 6749 Section 6: Refreshing an Access Token</a>
     * @see #refreshAsync(Executor, String, String...)
     */
    @Blocking
    public HttpResponse<String> refresh(HttpClient httpClient, String refreshToken, String... scopes) throws IOException, InterruptedException {
        return httpClient.send(buildRefreshTokenRequest(refreshToken, scopes), HttpResponse.BodyHandlers.ofString()); //TODO
    }

    @VisibleForTesting
    HttpRequest buildRefreshTokenRequest(String refreshToken, String... scopes) {
        return buildTokenRequest(Map.of(//
                "grant_type", "refresh_token", //
                "refresh_token", refreshToken, //
                "client_id", clientId, //
                "scope", String.join(" ", scopes)
        ));
    }

    /**
     * Creates a new HTTP request targeting the {@link #tokenEndpoint}.
     *
     * @param parameters Parameters to send in an {@code application/x-www-form-urlencoded} request body
     * @return A new http request
     */
    @Contract("_ -> new")
    HttpRequest buildTokenRequest(Map<String, String> parameters) {
        var urlencodedParams = URIUtil.buildQueryString(parameters);
        return HttpRequest.newBuilder(tokenEndpoint) //
                .header("Content-Type", "application/x-www-form-urlencoded") //
                .POST(HttpRequest.BodyPublishers.ofString(urlencodedParams)) //
                .timeout(requestTimeout) //
                .build();
    }

}
