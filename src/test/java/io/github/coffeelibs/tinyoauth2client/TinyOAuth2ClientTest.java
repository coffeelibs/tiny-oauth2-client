package io.github.coffeelibs.tinyoauth2client;

import io.github.coffeelibs.tinyoauth2client.util.URIUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;

public class TinyOAuth2ClientTest {

    @Test
    @DisplayName("authFlow(...)")
    public void testAuthFlow() {
        var client = new TinyOAuth2Client("my-client", URI.create("http://example.com/oauth2/token"));
        var authEndpoint = URI.create("https://login.example.com/");

        var authFlow = client.authFlow(authEndpoint);

        Assertions.assertSame(authFlow.client, client);
        Assertions.assertSame(authFlow.authEndpoint, authEndpoint);
        Assertions.assertNotNull(authFlow.pkce);
    }

    @Test
    @DisplayName("refreshAsync(executor, \"r3fr3sh70k3n\") sends refresh token request")
    public void testRefreshAsync() throws ExecutionException {
        var tokenEndpoint = URI.create("http://example.com/oauth2/token");
        var client = Mockito.spy(new TinyOAuth2Client("my-client", tokenEndpoint));
        var executor = Mockito.mock(Executor.class);
        var httpClient = Mockito.mock(HttpClient.class);
        var httpClientBuilder = Mockito.mock(HttpClient.Builder.class);
        var httpRequest = Mockito.mock(HttpRequest.class);
        var httpRespone = Mockito.mock(HttpResponse.class);
        try (var httpClientClass = Mockito.mockStatic(HttpClient.class)) {
            httpClientClass.when(HttpClient::newBuilder).thenReturn(httpClientBuilder);
            Mockito.doReturn(httpClient).when(httpClientBuilder).build();
            Mockito.doReturn(httpClientBuilder).when(httpClientBuilder).executor(Mockito.any());
            Mockito.doReturn(httpRequest).when(client).buildRefreshTokenRequest(Mockito.any());
            Mockito.doReturn(CompletableFuture.completedFuture(httpRespone)).when(httpClient).sendAsync(Mockito.any(), Mockito.any());

            var result = client.refreshAsync(executor, "r3fr3sh70k3n");

            Assertions.assertEquals(httpRespone, result.join());
            Mockito.verify(client).buildRefreshTokenRequest("r3fr3sh70k3n");
            Mockito.verify(httpClientBuilder).executor(executor);
            Mockito.verify(httpClient).sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
        }
    }

    @Test
    @DisplayName("refreshAsync(executor, \"r3fr3sh70k3n\", \"foo\", \"bar\") sends refresh token request")
    public void testRefreshAsyncWithScopes() throws ExecutionException {
        var tokenEndpoint = URI.create("http://example.com/oauth2/token");
        var client = Mockito.spy(new TinyOAuth2Client("my-client", tokenEndpoint));
        var executor = Mockito.mock(Executor.class);
        var httpClient = Mockito.mock(HttpClient.class);
        var httpClientBuilder = Mockito.mock(HttpClient.Builder.class);
        var httpRequest = Mockito.mock(HttpRequest.class);
        var httpRespone = Mockito.mock(HttpResponse.class);
        try (var httpClientClass = Mockito.mockStatic(HttpClient.class)) {
            httpClientClass.when(HttpClient::newBuilder).thenReturn(httpClientBuilder);
            Mockito.doReturn(httpClient).when(httpClientBuilder).build();
            Mockito.doReturn(httpClientBuilder).when(httpClientBuilder).executor(Mockito.any());
            Mockito.doReturn(httpRequest).when(client).buildRefreshTokenRequest(Mockito.any(), Mockito.any());
            Mockito.doReturn(CompletableFuture.completedFuture(httpRespone)).when(httpClient).sendAsync(Mockito.any(), Mockito.any());

            var result = client.refreshAsync(executor, "r3fr3sh70k3n", "foo", "bar");

            Assertions.assertEquals(httpRespone, result.join());
            Mockito.verify(client).buildRefreshTokenRequest("r3fr3sh70k3n", "foo", "bar");
            Mockito.verify(httpClientBuilder).executor(executor);
            Mockito.verify(httpClient).sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
        }
    }

    @Test
    @DisplayName("refresh(\"r3fr3sh70k3n\") sends refresh token request")
    public void testRefresh() throws IOException, InterruptedException {
        var tokenEndpoint = URI.create("http://example.com/oauth2/token");
        var client = Mockito.spy(new TinyOAuth2Client("my-client", tokenEndpoint));
        var httpClient = Mockito.mock(HttpClient.class);
        var httpRequest = Mockito.mock(HttpRequest.class);
        var httpRespone = Mockito.mock(HttpResponse.class);
        try (var httpClientClass = Mockito.mockStatic(HttpClient.class)) {
            httpClientClass.when(HttpClient::newHttpClient).thenReturn(httpClient);
            Mockito.doReturn(httpRequest).when(client).buildRefreshTokenRequest(Mockito.any());
            Mockito.doReturn(httpRespone).when(httpClient).send(Mockito.any(), Mockito.any());

            var result = client.refresh("r3fr3sh70k3n");

            Assertions.assertEquals(httpRespone, result);
            Mockito.verify(client).buildRefreshTokenRequest("r3fr3sh70k3n");
            Mockito.verify(httpClient).send(httpRequest, HttpResponse.BodyHandlers.ofString());
        }
    }

    @Test
    @DisplayName("refresh(\"r3fr3sh70k3n\", \"foo\", \"bar\") sends refresh token request")
    public void testRefreshWithScopes() throws IOException, InterruptedException {
        var tokenEndpoint = URI.create("http://example.com/oauth2/token");
        var client = Mockito.spy(new TinyOAuth2Client("my-client", tokenEndpoint));
        var httpClient = Mockito.mock(HttpClient.class);
        var httpRequest = Mockito.mock(HttpRequest.class);
        var httpRespone = Mockito.mock(HttpResponse.class);
        try (var httpClientClass = Mockito.mockStatic(HttpClient.class)) {
            httpClientClass.when(HttpClient::newHttpClient).thenReturn(httpClient);
            Mockito.doReturn(httpRequest).when(client).buildRefreshTokenRequest(Mockito.any(), Mockito.any());
            Mockito.doReturn(httpRespone).when(httpClient).send(Mockito.any(), Mockito.any());

            var result = client.refresh("r3fr3sh70k3n", "foo", "bar");

            Assertions.assertEquals(httpRespone, result);
            Mockito.verify(client).buildRefreshTokenRequest("r3fr3sh70k3n", "foo", "bar");
            Mockito.verify(httpClient).send(httpRequest, HttpResponse.BodyHandlers.ofString());
        }
    }

    @Test
    @DisplayName("buildRefreshTokenRequest(\"r3fr3sh70k3n\") builds new http request")
    public void testBuildRefreshTokenRequest() {
        var tokenEndpoint = URI.create("http://example.com/oauth2/token");
        var client = Mockito.spy(new TinyOAuth2Client("my-client", tokenEndpoint));
        var request = Mockito.mock(HttpRequest.class);
        Mockito.doReturn(request).when(client).buildTokenRequest(Mockito.any());

        var result = client.buildRefreshTokenRequest("r3fr3sh70k3n");

        Assertions.assertEquals(request, result);
        Mockito.verify(client).buildTokenRequest(Map.of(//
                "grant_type", "refresh_token", //
                "refresh_token", "r3fr3sh70k3n", //
                "client_id", "my-client", //
                "scope", ""
        ));
    }

    @Test
    @DisplayName("buildRefreshTokenRequest(\"r3fr3sh70k3n\", \"foo\", \"bar\") builds new http request")
    public void testBuildRefreshTokenRequestWithScopes() {
        var tokenEndpoint = URI.create("http://example.com/oauth2/token");
        var client = Mockito.spy(new TinyOAuth2Client("my-client", tokenEndpoint));
        var request = Mockito.mock(HttpRequest.class);
        Mockito.doReturn(request).when(client).buildTokenRequest(Mockito.any());

        var result = client.buildRefreshTokenRequest("r3fr3sh70k3n", "foo", "bar");

        Assertions.assertEquals(request, result);
        Mockito.verify(client).buildTokenRequest(Map.of(//
                "grant_type", "refresh_token", //
                "refresh_token", "r3fr3sh70k3n", //
                "client_id", "my-client", //
                "scope", "foo bar"
        ));
    }

    @Test
    @DisplayName("buildTokenRequest(...) creates new POST request with application/x-www-form-urlencoded params")
    public void testBuildTokenRequest() {
        var tokenEndpoint = URI.create("http://example.com/oauth2/token");
        var client = new TinyOAuth2Client("my-client", tokenEndpoint);
        var params = Map.of("query", "string", "mock", "true");
        var bodyPublisher = Mockito.mock(HttpRequest.BodyPublisher.class);
        try (var bodyPublishersClass = Mockito.mockStatic(HttpRequest.BodyPublishers.class);
             var uriUtilClass = Mockito.mockStatic(URIUtil.class)) {
            uriUtilClass.when(() -> URIUtil.buildQueryString(Mockito.any())).thenReturn("query=string&mock=true");
            bodyPublishersClass.when(() -> HttpRequest.BodyPublishers.ofString(Mockito.any())).thenReturn(bodyPublisher);

            var request = client.buildTokenRequest(params);

            uriUtilClass.verify(() -> URIUtil.buildQueryString(Mockito.same(params)));
            bodyPublishersClass.verify(() -> HttpRequest.BodyPublishers.ofString("query=string&mock=true"));
            Assertions.assertEquals(tokenEndpoint, request.uri());
            Assertions.assertEquals("POST", request.method());
            Assertions.assertEquals(bodyPublisher, request.bodyPublisher().get());
            Assertions.assertEquals("application/x-www-form-urlencoded", request.headers().firstValue("Content-Type").orElse(null));
        }

    }

}