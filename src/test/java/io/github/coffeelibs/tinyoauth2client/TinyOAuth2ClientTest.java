package io.github.coffeelibs.tinyoauth2client;

import io.github.coffeelibs.tinyoauth2client.util.URIUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

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

	@Nested
	@DisplayName("refresh(...)")
	public class RefreshTokens {

		private URI tokenEndpoint;
		private TinyOAuth2Client client;
		private HttpClient httpClient;
		private HttpResponse<String> httpRespone;
		private MockedStatic<HttpClient> httpClientClass;

		@BeforeEach
		@SuppressWarnings("unchecked")
		public void setup() throws IOException, InterruptedException {
			tokenEndpoint = URI.create("http://example.com/oauth2/token");
			client = new TinyOAuth2Client("my-client", tokenEndpoint);

			httpClient = Mockito.mock(HttpClient.class);
			httpRespone = Mockito.mock(HttpResponse.class);
			httpClientClass = Mockito.mockStatic(HttpClient.class);

			httpClientClass.when(HttpClient::newHttpClient).thenReturn(httpClient);
			Mockito.doReturn(httpRespone).when(httpClient).send(Mockito.any(), Mockito.any());
		}

		@AfterEach
		public void tearDown() {
			httpClientClass.close();
		}

		@Test
		@DisplayName("body contains all params")
		public void testRefresh() throws IOException, InterruptedException {
			Mockito.doReturn(200).when(httpRespone).statusCode();
			var bodyCaptor = ArgumentCaptor.forClass(String.class);
			var bodyPublisher = Mockito.mock(HttpRequest.BodyPublisher.class);
			try (var bodyPublishersClass = Mockito.mockStatic(HttpRequest.BodyPublishers.class)) {
				bodyPublishersClass.when(() -> HttpRequest.BodyPublishers.ofString(Mockito.any())).thenReturn(bodyPublisher);

				client.refresh("r3fr3sh70k3n", "offline_access");

				bodyPublishersClass.verify(() -> HttpRequest.BodyPublishers.ofString(bodyCaptor.capture()));
			}
			var body = bodyCaptor.getValue();
			var params = URIUtil.parseQueryString(body);
			Assertions.assertEquals("refresh_token", params.get("grant_type"));
			Assertions.assertEquals(client.clientId, params.get("client_id"));
			Assertions.assertEquals("r3fr3sh70k3n", params.get("refresh_token"));
			Assertions.assertEquals("offline_access", params.get("scope"));
		}

		@Test
		@DisplayName("send POST request to token endpoint")
		public void testGetAccessToken200() throws IOException, InterruptedException {
			Mockito.doReturn(200).when(httpRespone).statusCode();
			Mockito.doReturn("BODY").when(httpRespone).body();
			var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);

			var result = client.refresh("r3fr3sh70k3n");

			Assertions.assertEquals("BODY", result);
			Mockito.verify(httpClient).send(requestCaptor.capture(), Mockito.any());
			var request = requestCaptor.getValue();
			Assertions.assertSame(tokenEndpoint, request.uri());
			Assertions.assertEquals("POST", request.method());
			Assertions.assertEquals("application/x-www-form-urlencoded", request.headers().firstValue("Content-Type").orElse(null));
		}

		@Test
		@DisplayName("non-success response from token endpoint leads to IOException")
		public void testGetAccessToken404() {
			Mockito.doReturn(404).when(httpRespone).statusCode();

			Assertions.assertThrows(IOException.class, () -> client.refresh("r3fr3sh70k3n"));
		}

	}

}