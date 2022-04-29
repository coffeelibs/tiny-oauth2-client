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
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;

public class AuthFlowTest {

	private final TinyOAuth2Client client = new TinyOAuth2Client("my-client", URI.create("http://example.com/oauth2/token"));
	private final URI authEndpoint = URI.create("https://login.example.com/");
	private final PKCE pkce = new PKCE();

	@Nested
	@DisplayName("Configure")
	public class TestSetters {

		private final AuthFlow authFlow = new AuthFlow(client, authEndpoint, pkce);

		@Nested
		@DisplayName("test rediectPort")
		public class TestRedirectPort {

			@Test
			@DisplayName("withLocalPorts(AuthFlow.SYSTEM_ASSIGNED_PORT)")
			public void testWithSystemAssignedLocalPort() {
				Assertions.assertDoesNotThrow(() -> authFlow.setRedirectPort(AuthFlow.SYSTEM_ASSIGNED_PORT));

				Assertions.assertArrayEquals(new int[]{0}, authFlow.redirectPorts);
			}

			@Test
			@DisplayName("withLocalPorts(null)")
			public void testWithNullLocalPort() {
				Assertions.assertThrows(NullPointerException.class, () -> authFlow.setRedirectPort((int[]) null));
			}

			@Test
			@DisplayName("withLocalPorts(1234, 5678)")
			public void testWithFixedLocalPorts() {
				Assertions.assertDoesNotThrow(() -> authFlow.setRedirectPort(1234, 5678));

				Assertions.assertArrayEquals(new int[]{1234, 5678}, authFlow.redirectPorts);
			}

		}

		@Nested
		@DisplayName("test redirectPath")
		public class TestRedirectPath {

			@Test
			@DisplayName("default redirectPath")
			public void testDefaultLocalPath() {
				Assertions.assertTrue(authFlow.redirectPath.matches("/[\\w-]{16}"));
			}

			@Test
			@DisplayName("withLocalPath(null)")
			public void testWithNullLocalPath() {
				//noinspection ConstantConditions
				Assertions.assertThrows(NullPointerException.class, () -> authFlow.setRedirectPath(null));
			}

			@Test
			@DisplayName("withLocalPath(\"foo\")")
			public void testWithRelativeLocalPath() {
				Assertions.assertThrows(IllegalArgumentException.class, () -> authFlow.setRedirectPath("foo"));
			}

			@Test
			@DisplayName("withLocalPath(\"/foo\")")
			public void testWithAbsoluteLocalPath() {
				Assertions.assertDoesNotThrow(() -> authFlow.setRedirectPath("/foo"));

				Assertions.assertEquals("/foo", authFlow.redirectPath);
			}
		}

	}

	@Nested
	@SuppressWarnings("resource")
	@Timeout(1)
	@DisplayName("With configured AuthFlow")
	public class WithMockedRedirectTarget {

		private AuthFlow authFlow;
		private RedirectTarget redirectTarget;
		private MockedStatic<RedirectTarget> redirectTargetClass;
		private Consumer<URI> browser;

		@BeforeEach
		@SuppressWarnings({"unchecked"})
		public void setup() throws IOException {
			authFlow = new AuthFlow(client, authEndpoint, pkce);
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
			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser));

			redirectTargetClass.verify(() -> RedirectTarget.start(Mockito.matches("/[\\w-]{16}"), Mockito.any()));
		}

		@Test
		@DisplayName("authorize(...) with fixed path and port")
		public void testAuthorizeWithFixedPathAndPorts() {
			authFlow.setRedirectPath("/foo").setRedirectPort(1234, 5678);

			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser));

			redirectTargetClass.verify(() -> RedirectTarget.start("/foo", 1234, 5678));
		}

		@Test
		@DisplayName("authorize(...) calls redirectTarget.setSuccessResponse(...)")
		public void testConfigureSuccessResponse() {
			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser));

			Mockito.verify(redirectTarget).setSuccessResponse(authFlow.successResponse);
		}

		@Test
		@DisplayName("authorize(...) calls redirectTarget.setErrorResponse(...)")
		public void testConfigureErrorResponse() {
			Assertions.assertDoesNotThrow(() -> authFlow.authorize(browser));

			Mockito.verify(redirectTarget).setErrorResponse(authFlow.errorResponse);
		}

		@Test
		@DisplayName("authorize(...) with existing query string in authorization endpoint")
		public void testAuthorizeWithExistingQueryParams() throws IOException {
			var authEndpoint = URI.create("https://login.example.com/?existing_param=existing-value");
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

			private AuthFlow.AuthFlowWithCode authFlowWithCode;
			private HttpClient httpClient;
			private HttpResponse<String> httpRespone;
			private MockedStatic<HttpClient> httpClientClass;

			@BeforeEach
			@SuppressWarnings("unchecked")
			public void setup() throws IOException, InterruptedException {
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

				Assertions.assertThrows(IOException.class, () -> authFlowWithCode.getAccessToken());
			}

		}

	}

}