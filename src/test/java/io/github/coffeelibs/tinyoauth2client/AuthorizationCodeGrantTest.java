package io.github.coffeelibs.tinyoauth2client;

import io.github.coffeelibs.tinyoauth2client.http.RedirectTarget;
import io.github.coffeelibs.tinyoauth2client.http.response.Response;
import io.github.coffeelibs.tinyoauth2client.util.URIUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.internal.stubbing.answers.AnswersWithDelay;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.stream.Stream;

public class AuthorizationCodeGrantTest {

    private final TinyOAuth2Client client = Mockito.spy(new TinyOAuth2Client("my-client", URI.create("http://example.com/oauth2/token")));
    private final URI authEndpoint = URI.create("https://login.example.com/");
    private final PKCE pkce = new PKCE();

    @Nested
    @DisplayName("Configure")
    public class TestSetters {

        private AuthorizationCodeGrant grant;

        @BeforeEach
        public void setup() {
            grant = new AuthorizationCodeGrant(client, authEndpoint, pkce);
        }

        @Nested
        @DisplayName("successResponse")
        public class TestSuccessResponse {

            @Test
            @DisplayName("setSuccessResponse(null)")
            public void testNull() {
                Assertions.assertThrows(NullPointerException.class, () -> grant.setSuccessResponse(null));
            }

            @Test
            @DisplayName("setSuccessResponse(response)")
            public void testValidResponse() {
                var response = Response.empty(Response.Status.OK);

                Assertions.assertDoesNotThrow(() -> grant.setSuccessResponse(response));

                Assertions.assertEquals(response, grant.successResponse);
            }

        }

        @Nested
        @DisplayName("errorResponse")
        public class TestErrorResponse {

            @Test
            @DisplayName("setErrorResponse(null)")
            public void testNull() {
                Assertions.assertThrows(NullPointerException.class, () -> grant.setErrorResponse(null));
            }

            @Test
            @DisplayName("setErrorResponse(response)")
            public void testValidResponse() {
                var response = Response.empty(Response.Status.OK);

                Assertions.assertDoesNotThrow(() -> grant.setErrorResponse(response));

                Assertions.assertEquals(response, grant.errorResponse);
            }

        }

        @Nested
        @DisplayName("rediectPort")
        public class TestRedirectPort {

            @Test
            @DisplayName("defaults to AuthorizationCodeGrant.SYSTEM_ASSIGNED_PORT")
            public void testDefaultLocalPath() {
                Assertions.assertArrayEquals(AuthorizationCodeGrant.SYSTEM_ASSIGNED_PORT, grant.redirectPorts);
            }

            @Test
            @DisplayName("setRedirectPort(AuthorizationCodeGrant.SYSTEM_ASSIGNED_PORT)")
            public void testWithSystemAssignedLocalPort() {
                Assertions.assertDoesNotThrow(() -> grant.setRedirectPort(AuthorizationCodeGrant.SYSTEM_ASSIGNED_PORT));

                Assertions.assertArrayEquals(new int[]{0}, grant.redirectPorts);
            }

            @Test
            @DisplayName("setRedirectPort(null)")
            public void testWithNullLocalPort() {
                Assertions.assertThrows(NullPointerException.class, () -> grant.setRedirectPort((int[]) null));
            }

            @Test
            @DisplayName("setRedirectPort(1234, 5678)")
            public void testWithFixedLocalPorts() {
                Assertions.assertDoesNotThrow(() -> grant.setRedirectPort(1234, 5678));

                Assertions.assertArrayEquals(new int[]{1234, 5678}, grant.redirectPorts);
            }

        }

        @Nested
        @DisplayName("redirectPath")
        public class TestRedirectPath {

            @Test
            @DisplayName("defaults to autogenerated value")
            public void testDefaultLocalPath() {
                Assertions.assertTrue(grant.redirectPath.matches("/[\\w-]{16}"));
            }

            @Test
            @DisplayName("setRedirectPath(null)")
            public void testWithNullLocalPath() {
                //noinspection ConstantConditions
                Assertions.assertThrows(NullPointerException.class, () -> grant.setRedirectPath(null));
            }

            @Test
            @DisplayName("setRedirectPath(\"foo\")")
            public void testWithRelativeLocalPath() {
                Assertions.assertThrows(IllegalArgumentException.class, () -> grant.setRedirectPath("foo"));
            }

            @Test
            @DisplayName("setRedirectPath(\"/foo\")")
            public void testWithAbsoluteLocalPath() {
                Assertions.assertDoesNotThrow(() -> grant.setRedirectPath("/foo"));

                Assertions.assertEquals("/foo", grant.redirectPath);
            }
        }

    }

    @DisplayName("test buildAuthUri(...)")
    @ParameterizedTest(name = "buildAuthUri(\"{1}\", \"{2}\", {3})")
    @MethodSource
    public void testBuildAuthUri(URI authEndpoint, URI redirectEndpoint, String csrfToken, Set<String> scopes, URI expectedResult) {
        var pkce = Mockito.mock(PKCE.class);
        Mockito.doReturn("C0D3Ch4ll3ng3").when(pkce).getChallenge();
        var grant = new AuthorizationCodeGrant(client, authEndpoint, pkce);

        var result = grant.buildAuthUri(redirectEndpoint, csrfToken, scopes);

        Assertions.assertEquals(expectedResult.getScheme(), result.getScheme());
        Assertions.assertEquals(expectedResult.getAuthority(), result.getAuthority());
        Assertions.assertEquals(expectedResult.getPath(), result.getPath());
        // query order might differ:
        var expectedQueryParams = URIUtil.parseQueryString(expectedResult.getRawQuery());
        var queryParams = URIUtil.parseQueryString(result.getRawQuery());
        Assertions.assertEquals(expectedQueryParams, queryParams);
    }

    public static Stream<Arguments> testBuildAuthUri() {
        return Stream.of( //
                Arguments.of(URI.create("https://login.example.com/"), URI.create("http://127.0.0.1/callback"), "token", Set.of(), URI.create("https://login.example.com/?state=token&code_challenge=C0D3Ch4ll3ng3&response_type=code&client_id=my-client&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")), //
                Arguments.of(URI.create("https://login.example.com/?foo=bar"), URI.create("http://127.0.0.1/callback"), "token", Set.of(""), URI.create("https://login.example.com/?state=token&scope&code_challenge=C0D3Ch4ll3ng3&response_type=code&client_id=my-client&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&foo=bar")), //
                Arguments.of(URI.create("https://login.example.com/"), URI.create("http://127.0.0.1/callback"), "t0k3n", Set.of("offline_access"), URI.create("https://login.example.com/?state=t0k3n&scope=offline_access&code_challenge=C0D3Ch4ll3ng3&response_type=code&client_id=my-client&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback")), //
                Arguments.of(URI.create("https://login.example.com/?foo=bar"), URI.create("http://127.0.0.1/callback"), "token", Set.of("offline_access"), URI.create("https://login.example.com/?state=token&scope=offline_access&code_challenge=C0D3Ch4ll3ng3&response_type=code&client_id=my-client&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&foo=bar")), //
                Arguments.of(URI.create("https://login.example.com/?foo=bar"), URI.create("http://127.0.0.1/c?all=back"), "token", Set.of("offline_access"), URI.create("https://login.example.com/?state=token&scope=offline_access&code_challenge=C0D3Ch4ll3ng3&response_type=code&client_id=my-client&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%2Fc%3Fall%3Dback&foo=bar"))
        );
    }

    @Nested
    @SuppressWarnings("resource")
    @Timeout(1)
    @DisplayName("With configured AuthorizationCodeGrant")
    public class WithMockedRedirectTarget {

        private AuthorizationCodeGrant grant;
        private RedirectTarget redirectTarget;
        private MockedStatic<RedirectTarget> redirectTargetClass;
        private Consumer<URI> browser;

        @BeforeEach
        @SuppressWarnings({"unchecked"})
        public void setup() throws IOException {
            grant = new AuthorizationCodeGrant(client, authEndpoint, pkce);
            redirectTarget = Mockito.mock(RedirectTarget.class);
            redirectTargetClass = Mockito.mockStatic(RedirectTarget.class);
            redirectTargetClass.when(() -> RedirectTarget.start(Mockito.any(), Mockito.any(int[].class))).thenReturn(redirectTarget);
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
        @DisplayName("requestAuthCode(...) uses configured path and ports")
        public void testAuthorizeWithFixedPathAndPorts() {
            grant.setRedirectPath("/foo").setRedirectPort(1234, 5678);

            Assertions.assertDoesNotThrow(() -> grant.requestAuthCode(browser));

            redirectTargetClass.verify(() -> RedirectTarget.start(grant.redirectPath, grant.redirectPorts));
        }

        @Test
        @DisplayName("requestAuthCode(...) calls redirectTarget.setSuccessResponse(...)")
        public void testApplySuccessResponse() {
            Assertions.assertDoesNotThrow(() -> grant.requestAuthCode(browser));

            Mockito.verify(redirectTarget).setSuccessResponse(grant.successResponse);
        }

        @Test
        @DisplayName("requestAuthCode(...) calls redirectTarget.setErrorResponse(...)")
        public void testApplyErrorResponse() {
            Assertions.assertDoesNotThrow(() -> grant.requestAuthCode(browser));

            Mockito.verify(redirectTarget).setErrorResponse(grant.errorResponse);
        }

        @Test
        @DisplayName("requestAuthCode(...) opens browser with URI returned from buildAuthUri(...)")
        public void testAuthorizeWithExistingQueryParams() throws IOException {
            var grant = Mockito.spy(new AuthorizationCodeGrant(client, authEndpoint, pkce));
            var completeUri = URI.create("https://login.example.com/?some&more&params");
            Mockito.doReturn(completeUri).when(grant).buildAuthUri(Mockito.any(), Mockito.any(), Mockito.any());

            var result = grant.requestAuthCode(browser);

            Assertions.assertInstanceOf(AuthorizationCodeGrant.WithAuthorizationCode.class, result);
            Mockito.verify(grant).buildAuthUri(redirectTarget.getRedirectUri(), redirectTarget.getCsrfToken(), Set.of());
            Mockito.verify(browser).accept(completeUri);
        }

        @Nested
        @DisplayName("After receiving auth code")
        public class WithAuthCode {

            @Test
            @DisplayName("buildTokenRequest() builds new http request")
            public void testBuildTokenRequest() {
                var grantWithCode = grant.new WithAuthorizationCode("redirect-uri", "auth-code");
                var requestBuilder = Mockito.mock(HttpRequest.Builder.class);
                var request = Mockito.mock(HttpRequest.class);
                Mockito.doReturn(requestBuilder).when(client).createTokenRequest(Mockito.any());
                Mockito.doReturn(request).when(requestBuilder).build();

                var result = grantWithCode.buildTokenRequest();

                Assertions.assertEquals(request, result);
                Mockito.verify(client).createTokenRequest(Map.of(//
                        "grant_type", "authorization_code", //
                        "client_id", client.clientId, //
                        "code_verifier", pkce.getVerifier(), //
                        "code", "auth-code", //
                        "redirect_uri", "redirect-uri" //
                ));
            }

            @Test
            @DisplayName("getAccessTokenAsync(httpClient) sends access token request")
            public void testGetAccessTokenAsync() {
                var grantWithCode = Mockito.spy(grant.new WithAuthorizationCode("redirect-uri", "auth-code"));
                var httpClient = Mockito.mock(HttpClient.class);
                var httpRequest = Mockito.mock(HttpRequest.class);
                var httpRespone = Mockito.mock(HttpResponse.class);
                Mockito.doReturn(httpRequest).when(grantWithCode).buildTokenRequest();
                Mockito.doReturn(CompletableFuture.completedFuture(httpRespone)).when(httpClient).sendAsync(Mockito.any(), Mockito.any());

                var result = grantWithCode.getAccessTokenAsync(httpClient);

                Assertions.assertEquals(httpRespone, result.join());
                Mockito.verify(grantWithCode).buildTokenRequest();
                Mockito.verify(httpClient).sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
            }

            @Test
            @DisplayName("getAccessToken(httpClient) sends access token request")
            public void testGetAccessToken() throws IOException, InterruptedException {
                var grantWithCode = Mockito.spy(grant.new WithAuthorizationCode("redirect-uri", "auth-code"));
                var httpClient = Mockito.mock(HttpClient.class);
                var httpRequest = Mockito.mock(HttpRequest.class);
                var httpRespone = Mockito.mock(HttpResponse.class);
                Mockito.doReturn(httpRequest).when(grantWithCode).buildTokenRequest();
                Mockito.doReturn(httpRespone).when(httpClient).send(Mockito.any(), Mockito.any());

                var result = grantWithCode.getAccessToken(httpClient);

                Assertions.assertEquals(httpRespone, result);
                Mockito.verify(grantWithCode).buildTokenRequest();
                Mockito.verify(httpClient).send(httpRequest, HttpResponse.BodyHandlers.ofString());
            }

        }

    }

    @Test
    @Timeout(3)
    @DisplayName("authorizeAsync(httpClient,...) runs requestAuthCode() and getAccessToken()")
    @SuppressWarnings("unchecked")
    public void testAuthorizeAsync() throws IOException, ExecutionException, InterruptedException {
        Consumer<URI> browser = Mockito.mock(Consumer.class);
        var httpClient = Mockito.mock(HttpClient.class);
        Mockito.when(httpClient.executor()).thenReturn(Optional.empty());
        var grant = Mockito.spy(new AuthorizationCodeGrant(client, authEndpoint, pkce));
        var grantWithCode = Mockito.mock(AuthorizationCodeGrant.WithAuthorizationCode.class);
        var httpResponse = Mockito.mock(HttpResponse.class);
        Mockito.doAnswer(new AnswersWithDelay(1000, invocation -> grantWithCode)).when(grant).requestAuthCode(Mockito.any());
        Mockito.doReturn(CompletableFuture.completedFuture(httpResponse)).when(grantWithCode).getAccessTokenAsync(Mockito.any());

        var result = grant.authorizeAsync(httpClient, browser);

        Assertions.assertEquals(httpResponse, result.get());
    }

    @Test
    @DisplayName("authorizeAsync(...) returns failed future on error during requestAuthCode(...)")
    @SuppressWarnings("unchecked")
    public void testAuthorizeAsyncWithError1() throws IOException {
        Consumer<URI> browser = Mockito.mock(Consumer.class);
        var httpClient = HttpClient.newBuilder().executor(Runnable::run).build();
        var grant = Mockito.spy(new AuthorizationCodeGrant(client, authEndpoint, pkce));
        Mockito.doThrow(new IOException("error")).when(grant).requestAuthCode(Mockito.any());


        var result = grant.authorizeAsync(httpClient, browser);

        Assertions.assertTrue(result.isCompletedExceptionally());
    }

    @Test
    @DisplayName("authorizeAsync(...) returns failed future on error during getAccessTokenAsync(...)")
    @SuppressWarnings("unchecked")
    public void testAuthorizeAsyncWithError2() throws IOException {
        Consumer<URI> browser = Mockito.mock(Consumer.class);
        var httpClient = HttpClient.newBuilder().executor(Runnable::run).build();
        var grant = Mockito.spy(new AuthorizationCodeGrant(client, authEndpoint, pkce));
        var grantWithCode = Mockito.mock(AuthorizationCodeGrant.WithAuthorizationCode.class);
        Mockito.doReturn(grantWithCode).when(grant).requestAuthCode(Mockito.any());

        var result = grant.authorizeAsync(httpClient, browser);

        Assertions.assertTrue(result.isCompletedExceptionally());
    }

    @Test
    @DisplayName("authorize(...) runs requestAuthCode() and getAccessToken()")
    @SuppressWarnings("unchecked")
    public void testAuthorize() throws IOException, InterruptedException {
        Consumer<URI> browser = Mockito.mock(Consumer.class);
        var httpClient = Mockito.mock(HttpClient.class);
        var grant = Mockito.spy(new AuthorizationCodeGrant(client, authEndpoint, pkce));
        var grantWithCode = Mockito.mock(AuthorizationCodeGrant.WithAuthorizationCode.class);
        var httpResponse = Mockito.mock(HttpResponse.class);
        Mockito.doReturn(grantWithCode).when(grant).requestAuthCode(Mockito.any());
        Mockito.doReturn(httpResponse).when(grantWithCode).getAccessToken(httpClient);

        var result = grant.authorize(httpClient, browser);

        Assertions.assertEquals(httpResponse, result);
    }

}