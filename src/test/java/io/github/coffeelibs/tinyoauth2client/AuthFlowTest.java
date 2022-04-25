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
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

public class AuthFlowTest {

	@Test
	@DisplayName("asClient(...) returns new instance")
	public void testCreateInstance() {
		var instance = AuthFlow.asClient("my-client");

		Assertions.assertInstanceOf(AuthFlow.class, instance);
	}

	@Test
	@SuppressWarnings("unchecked")
	@DisplayName("test conventience authorize(authEndpoint, browser)")
	public void testConvenienceAuthorize() throws IOException {
		var authFlow = Mockito.mock(AuthFlow.class);
		URI authEndpoint = Mockito.mock(URI.class);
		Consumer<URI> browser = Mockito.mock(Consumer.class);
		Mockito.doCallRealMethod().when(authFlow).authorize(authEndpoint, browser);

		authFlow.authorize(authEndpoint, browser);

		Mockito.verify(authFlow).authorize(Mockito.same(authEndpoint), Mockito.same(browser), Mockito.eq(Set.of()), Mockito.anyString());
	}

	@Nested
	@Timeout(1)
	@DisplayName("With mocked redirect target")
	public class WithMockedRedirectTarget {

		private RedirectTarget redirectTarget;
		private MockedStatic<RedirectTarget> redirectTargetClass;
		private CountDownLatch redirected;

		@BeforeEach
		public void setup() throws IOException {
			redirectTarget = Mockito.mock(RedirectTarget.class);
			redirectTargetClass = Mockito.mockStatic(RedirectTarget.class);
			redirectTargetClass.when(() -> RedirectTarget.start("/foo", 1234)).thenReturn(redirectTarget);
			redirected = new CountDownLatch(1);

			Mockito.doReturn(URI.create("http://127.0.0.1:1234/foo")).when(redirectTarget).getRedirectUri();
			Mockito.doReturn("csrf-token").when(redirectTarget).getCsrfToken();
			Mockito.doAnswer(invocation -> {
				redirected.await();
				return "authCode";
			}).when(redirectTarget).receive();
		}

		@AfterEach
		public void tearDown() {
			redirectTargetClass.close();
		}

		@Test
		@DisplayName("authorize(...) succeeds if browser redirects to URI")
		public void testAuthorize() throws IOException {
			URI authEndpoint = URI.create("https://login.example.com/?existing_param=existing-value");
			AtomicReference<URI> browsedUri = new AtomicReference<>();
			Consumer<URI> browser = uri -> {
				browsedUri.set(uri);
				redirected.countDown();
			};
			var authFlow = AuthFlow.asClient("my-client");

			var result = authFlow.authorize(authEndpoint, browser, Set.of("scope1", "scope2"), "/foo", 1234);

			Assertions.assertInstanceOf(AuthFlow.AuthFlowWithCode.class, result);
			Assertions.assertNotNull(browsedUri.get());
			Assertions.assertNotNull(browsedUri.get().getRawQuery());
			var queryParams = URIUtil.parseQueryString(browsedUri.get().getRawQuery());
			Assertions.assertEquals("existing-value", queryParams.get("existing_param"));
			Assertions.assertEquals(authFlow.clientId, queryParams.get("client_id"));
			Assertions.assertEquals("code", queryParams.get("response_type"));
			Assertions.assertEquals(redirectTarget.getCsrfToken(), queryParams.get("state"));
			Assertions.assertEquals("S256", queryParams.get("code_challenge_method"));
			Assertions.assertEquals(authFlow.pkce.challenge, queryParams.get("code_challenge"));
			Assertions.assertEquals(redirectTarget.getRedirectUri().toString(), queryParams.get("redirect_uri"));
			Assertions.assertTrue(queryParams.get("scope").contains("scope1"));
			Assertions.assertTrue(queryParams.get("scope").contains("scope2"));
		}

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
			authFlow = AuthFlow.asClient("my-client");
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
			var tokenEndpoint = URI.create("http://example.com/oauth2/token");
			var bodyCaptor = ArgumentCaptor.forClass(String.class);
			var replacementBody = HttpRequest.BodyPublishers.ofString("foo");
			try (var bodyPublishersClass = Mockito.mockStatic(HttpRequest.BodyPublishers.class)) {
				bodyPublishersClass.when(() -> HttpRequest.BodyPublishers.ofString(Mockito.any())).thenReturn(replacementBody);

				authFlowWithCode.getAccessToken(tokenEndpoint);

				bodyPublishersClass.verify(() -> HttpRequest.BodyPublishers.ofString(bodyCaptor.capture()));
			}
			var body = bodyCaptor.getValue();
			var params = URIUtil.parseQueryString(body);
			Assertions.assertEquals("authorization_code", params.get("grant_type"));
			Assertions.assertEquals(authFlow.clientId, params.get("client_id"));
			Assertions.assertEquals("auth-code", params.get("code"));
			Assertions.assertEquals("redirect-uri", params.get("redirect_uri"));
			Assertions.assertEquals(authFlow.pkce.verifier, params.get("code_verifier"));
		}

		@Test
		@DisplayName("send POST request to token endpoint")
		public void testGetAccessToken200() throws IOException, InterruptedException {
			Mockito.doReturn(200).when(httpRespone).statusCode();
			Mockito.doReturn("BODY").when(httpRespone).body();
			var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
			var tokenEndpoint = URI.create("http://example.com/oauth2/token");

			var result = authFlowWithCode.getAccessToken(tokenEndpoint);

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
			var tokenEndpoint = URI.create("http://example.com/oauth2/token");

			Assertions.assertThrows(IOException.class, () -> authFlowWithCode.getAccessToken(tokenEndpoint));
		}

	}

}