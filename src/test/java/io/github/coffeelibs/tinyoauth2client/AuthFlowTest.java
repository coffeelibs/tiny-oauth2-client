package io.github.coffeelibs.tinyoauth2client;

import io.github.coffeelibs.tinyoauth2client.http.RedirectTarget;
import io.github.coffeelibs.tinyoauth2client.util.URIUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;

public class AuthFlowTest {

	@Test
	@SuppressWarnings("unchecked")
	@DisplayName("test conventience authorize(browser)")
	public void testConvenienceAuthorize() throws IOException {
		var authFlow = Mockito.mock(AuthFlow.class);
		Consumer<URI> browser = Mockito.mock(Consumer.class);
		Mockito.doCallRealMethod().when(authFlow).authorize(browser);

		authFlow.authorize(browser);

		Mockito.verify(authFlow).authorize(Mockito.same(browser), Mockito.eq(Set.of()), Mockito.anyString());
	}

	@Nested
	@SuppressWarnings("resource")
	@Timeout(1)
	@DisplayName("With mocked redirect target")
	public class WithMockedRedirectTarget {

		private TinyOAuth2Client client;
		private URI authEndpoint;
		private PKCE pkce;
		private RedirectTarget redirectTarget;
		private MockedStatic<RedirectTarget> redirectTargetClass;
		private Consumer<URI> browser;

		@BeforeEach
		@SuppressWarnings({"unchecked"})
		public void setup() throws IOException {
			client = new TinyOAuth2Client("my-client", URI.create("http://example.com/oauth2/token"));
			authEndpoint = URI.create("https://login.example.com/");
			pkce = new PKCE();
			redirectTarget = Mockito.mock(RedirectTarget.class);
			redirectTargetClass = Mockito.mockStatic(RedirectTarget.class);
			redirectTargetClass.when(() -> RedirectTarget.start(Mockito.any(), Mockito.any())).thenReturn(redirectTarget);
			browser = Mockito.mock(Consumer.class);

			var redirected = new CountDownLatch(1);
			Mockito.doReturn(URI.create("http://127.0.0.1:1234/foo")).when(redirectTarget).getRedirectUri();
			Mockito.doReturn("csrf-token").when(redirectTarget).getCsrfToken();
			Mockito.doAnswer(invocation -> {
				redirected.await();
				return "authCode";
			}).when(redirectTarget).receive();
			Mockito.doAnswer(invocation -> {
				redirected.countDown();
				return null;
			}).when(browser).accept(Mockito.any());
		}

		@AfterEach
		public void tearDown() {
			redirectTargetClass.close();
		}

		@Test
		@DisplayName("authorize(...) with random path")
		public void testAuthorizeWithRandomPath() {
			var authFlow = new AuthFlow(client, authEndpoint, pkce);

			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser));

			redirectTargetClass.verify(() -> RedirectTarget.start(Mockito.matches("/[0-9a-zA-Z_-]{4,}")));
		}

		@Test
		@DisplayName("authorize(...) with fixed path and port")
		public void testAuthorizeWithFixedPathAndPorts() {
			var authFlow = new AuthFlow(client, authEndpoint, pkce);

			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser, Set.of("scope1", "scope2"), "/foo", 1234, 5678));

			redirectTargetClass.verify(() -> RedirectTarget.start("/foo", 1234, 5678));
		}

		@Test
		@DisplayName("withSuccessHtml(...) gets applied during authorize(...)")
		public void testWithSuccessHtml() {
			var authFlow = new AuthFlow(client, authEndpoint, pkce).withSuccessHtml("test");

			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser));

			Mockito.verify(redirectTarget).setSuccessResponse(Mockito.notNull());
		}

		@Test
		@DisplayName("withSuccessRedirect(...) gets applied during authorize(...)")
		public void testWithSuccessRedirect() {
			var authFlow = new AuthFlow(client, authEndpoint, pkce).withSuccessRedirect(URI.create("https://example.com"));

			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser));

			Mockito.verify(redirectTarget).setSuccessResponse(Mockito.notNull());
		}

		@Test
		@DisplayName("withErrorRedirect(...) gets applied during authorize(...)")
		public void testWithErrorRedirect() {
			var authFlow = new AuthFlow(client, authEndpoint, pkce).withErrorRedirect(URI.create("https://example.com"));

			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser));

			Mockito.verify(redirectTarget).setErrorResponse(Mockito.notNull());
		}

		@Test
		@DisplayName("withErrorHtml(...) gets applied during authorize(...)")
		public void testWithErrorHtml() {
			var authFlow = new AuthFlow(client, authEndpoint, pkce).withErrorHtml("test");

			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser));

			Mockito.verify(redirectTarget).setErrorResponse(Mockito.notNull());
		}

		@Test
		@DisplayName("authorize(...) with existing query string in authorization endpoint")
		public void testAuthorizeWithExistingQueryParams() throws IOException {
			authEndpoint = URI.create("https://login.example.com/?existing_param=existing-value");
			var authFlow = new AuthFlow(client, authEndpoint, pkce);

			var result = authFlow.authorize(browser);

			Assertions.assertInstanceOf(AuthFlow.AuthFlowWithCode.class, result);
			var browsedUriCaptor = ArgumentCaptor.forClass(URI.class);
			Mockito.verify(browser).accept(browsedUriCaptor.capture());
			var browsedUri = browsedUriCaptor.getValue();
			Assertions.assertNotNull(browsedUri);
			Assertions.assertNotNull(browsedUri.getRawQuery());
			var queryParams = URIUtil.parseQueryString(browsedUri.getRawQuery());
			Assertions.assertEquals("existing-value", queryParams.get("existing_param"));
			Assertions.assertEquals("code", queryParams.get("response_type"));
		}

		@Test
		@DisplayName("authorize(...) with custom scopes")
		public void testAuthorize() throws IOException {
			var authFlow = new AuthFlow(client, authEndpoint, pkce);

			var result = authFlow.authorize(browser, "scope1", "scope2");

			Assertions.assertInstanceOf(AuthFlow.AuthFlowWithCode.class, result);
			var browsedUriCaptor = ArgumentCaptor.forClass(URI.class);
			Mockito.verify(browser).accept(browsedUriCaptor.capture());
			var browsedUri = browsedUriCaptor.getValue();
			Assertions.assertNotNull(browsedUri);
			Assertions.assertNotNull(browsedUri.getRawQuery());
			var queryParams = URIUtil.parseQueryString(browsedUri.getRawQuery());
			Assertions.assertEquals(client.clientId, queryParams.get("client_id"));
			Assertions.assertEquals("code", queryParams.get("response_type"));
			Assertions.assertEquals(redirectTarget.getCsrfToken(), queryParams.get("state"));
			Assertions.assertEquals("S256", queryParams.get("code_challenge_method"));
			Assertions.assertEquals(pkce.challenge, queryParams.get("code_challenge"));
			Assertions.assertEquals(redirectTarget.getRedirectUri().toString(), queryParams.get("redirect_uri"));
			Assertions.assertTrue(queryParams.get("scope").contains("scope1"));
			Assertions.assertTrue(queryParams.get("scope").contains("scope2"));
		}

		@Nested
		@DisplayName("After receiving auth code")
		public class WithAuthCode {

			private AuthFlow authFlow;
			private AuthFlow.AuthFlowWithCode authFlowWithCode;
			private HttpClient httpClient;
			private HttpResponse<String> httpRespone;
			private MockedStatic<HttpClient> httpClientClass;

			@BeforeEach
			@SuppressWarnings("unchecked")
			public void setup() throws IOException, InterruptedException {
				authFlow = new AuthFlow(client, authEndpoint, pkce);
				authFlowWithCode = authFlow.new AuthFlowWithCode("redirect-uri", "auth-code");

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
			public void testGetAccessTokenQuery() throws IOException, InterruptedException {
				Mockito.doReturn(200).when(httpRespone).statusCode();
				var bodyCaptor = ArgumentCaptor.forClass(String.class);
				var bodyPublisher = Mockito.mock(HttpRequest.BodyPublisher.class);
				try (var bodyPublishersClass = Mockito.mockStatic(HttpRequest.BodyPublishers.class)) {
					bodyPublishersClass.when(() -> HttpRequest.BodyPublishers.ofString(Mockito.any())).thenReturn(bodyPublisher);

					authFlowWithCode.getAccessToken();

					bodyPublishersClass.verify(() -> HttpRequest.BodyPublishers.ofString(bodyCaptor.capture()));
				}
				var body = bodyCaptor.getValue();
				var params = URIUtil.parseQueryString(body);
				Assertions.assertEquals("authorization_code", params.get("grant_type"));
				Assertions.assertEquals(client.clientId, params.get("client_id"));
				Assertions.assertEquals("auth-code", params.get("code"));
				Assertions.assertEquals("redirect-uri", params.get("redirect_uri"));
				Assertions.assertEquals(pkce.verifier, params.get("code_verifier"));
			}

			@Test
			@DisplayName("send POST request to token endpoint")
			public void testGetAccessToken200() throws IOException, InterruptedException {
				Mockito.doReturn(200).when(httpRespone).statusCode();
				Mockito.doReturn("BODY").when(httpRespone).body();
				var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);

				var result = authFlowWithCode.getAccessToken();

				Assertions.assertEquals("BODY", result);
				Mockito.verify(httpClient).send(requestCaptor.capture(), Mockito.any());
				var request = requestCaptor.getValue();
				Assertions.assertSame(client.tokenEndpoint, request.uri());
				Assertions.assertEquals("POST", request.method());
				Assertions.assertEquals("application/x-www-form-urlencoded", request.headers().firstValue("Content-Type").orElse(null));
			}

			@Test
			@DisplayName("non-success response from token endpoint leads to IOException")
			public void testGetAccessToken404() {
				Mockito.doReturn(404).when(httpRespone).statusCode();
				var tokenEndpoint = URI.create("http://example.com/oauth2/token");

				Assertions.assertThrows(IOException.class, () -> authFlowWithCode.getAccessToken());
			}

		}

	}

}