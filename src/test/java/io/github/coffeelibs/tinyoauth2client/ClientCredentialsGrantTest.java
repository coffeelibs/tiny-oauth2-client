package io.github.coffeelibs.tinyoauth2client;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ClientCredentialsGrantTest {

	private final TinyOAuth2Client client = Mockito.spy(new TinyOAuth2Client("Aladdin", URI.create("http://example.com/oauth2/token")));

	@DisplayName("build basic auth header")
	@ParameterizedTest(name = "{0}:{1} -> {2}")
	@CsvSource({
			// from https://datatracker.ietf.org/doc/html/rfc7617:
			"Aladdin, open sesame, Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
			"test, 123£, Basic dGVzdDoxMjPCow==",
	})
	public void testBuildBasicAuthHeader(String username, String password, String expectedResult) {
		var result = ClientCredentialsGrant.buildBasicAuthHeader(StandardCharsets.UTF_8, username, password);

		Assertions.assertEquals(expectedResult, result);
	}

	@Test
	@DisplayName("buildTokenRequest() builds new http request")
	public void testBuildTokenRequest() {
		var grant = new ClientCredentialsGrant(client, StandardCharsets.UTF_8, "open sesame");
		var requestBuilder = Mockito.mock(HttpRequest.Builder.class);
		var request = Mockito.mock(HttpRequest.class);
		Mockito.doReturn(requestBuilder).when(client).createTokenRequest(Mockito.any());
		Mockito.doReturn(request).when(requestBuilder).build();

		var result = grant.buildTokenRequest(List.of("foo", "bar"));

		Assertions.assertEquals(request, result);
		Mockito.verify(client).createTokenRequest(Map.of(//
				"grant_type", "client_credentials", //
				"scope", "foo bar"
		));
		Mockito.verify(requestBuilder).setHeader("Authorization", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
	}

	@Test
	@DisplayName("authorize(...) sends access token request")
	@SuppressWarnings("unchecked")
	public void testAuthorize() throws IOException, InterruptedException {
		var grant = Mockito.spy(new ClientCredentialsGrant(client, StandardCharsets.UTF_8, "open sesame"));
		var httpClient = Mockito.mock(HttpClient.class);
		var httpRequest = Mockito.mock(HttpRequest.class);
		var httpRespone = Mockito.mock(HttpResponse.class);
		Mockito.doReturn(httpRequest).when(grant).buildTokenRequest(Mockito.any());
		Mockito.doReturn(httpRespone).when(httpClient).send(Mockito.any(), Mockito.any());

		var result = grant.authorize(httpClient);

		Assertions.assertEquals(httpRespone, result);
		Mockito.verify(httpClient).send(httpRequest, HttpResponse.BodyHandlers.ofString());
	}

	@Test
	@DisplayName("authorizeAsync(...) sends access token request")
	@SuppressWarnings("unchecked")
	public void testAuthorizeAsync() throws IOException, InterruptedException {
		var grant = Mockito.spy(new ClientCredentialsGrant(client, StandardCharsets.UTF_8, "open sesame"));
		var httpClient = Mockito.mock(HttpClient.class);
		var httpRequest = Mockito.mock(HttpRequest.class);
		var httpRespone = Mockito.mock(HttpResponse.class);
		Mockito.doReturn(httpRequest).when(grant).buildTokenRequest(Mockito.any());
		Mockito.doReturn(CompletableFuture.completedFuture(httpRespone)).when(httpClient).sendAsync(Mockito.any(), Mockito.any());

		var result = grant.authorizeAsync(httpClient);

		Assertions.assertEquals(httpRespone, result.join());
		Mockito.verify(httpClient).sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
	}

}