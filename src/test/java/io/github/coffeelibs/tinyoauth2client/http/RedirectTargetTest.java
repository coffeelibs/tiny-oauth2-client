package io.github.coffeelibs.tinyoauth2client.http;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.channels.AlreadyBoundException;
import java.nio.channels.Channels;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;

@Timeout(value = 3)
@SuppressWarnings("resource")
public class RedirectTargetTest {

	@Test
	@DisplayName("start() doesn't accept a relative path")
	public void testStartWithRelativePath() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> RedirectTarget.start("hello"));
	}

	@Test
	@DisplayName("setSuccessResponse() fails on null")
	public void testSetSuccessNull() throws IOException {
		try (var target = RedirectTarget.start("/")) {
			Assertions.assertThrows(NullPointerException.class, () -> target.setSuccessResponse(null));
		}
	}

	@Test
	@DisplayName("setSuccessResponse() succeeds on non-null")
	public void testSetSuccessNonNull() throws IOException {
		try (var target = RedirectTarget.start("/")) {
			Assertions.assertDoesNotThrow(() -> target.setSuccessResponse(Response.empty(Response.Status.OK)));
		}
	}

	@Test
	@DisplayName("setErrorResponse() fails on null")
	public void testSetErrorNull() throws IOException {
		try (var target = RedirectTarget.start("/")) {
			Assertions.assertThrows(NullPointerException.class, () -> target.setErrorResponse(null));
		}
	}

	@Test
	@DisplayName("setErrorResponse() succeeds on non-null")
	public void testSetErrorNonNull() throws IOException {
		try (var target = RedirectTarget.start("/")) {
			Assertions.assertDoesNotThrow(() -> target.setErrorResponse(Response.empty(Response.Status.OK)));
		}
	}

	@Test
	@DisplayName("start() doesn't leak resource on error")
	public void testStartExceptionally() throws IOException {
		var ch = Mockito.mock(ServerSocketChannel.class);
		Mockito.doThrow(new AlreadyBoundException()).when(ch).bind(Mockito.any());
		try (var socketChannelClass = Mockito.mockStatic(ServerSocketChannel.class)) {
			socketChannelClass.when(ServerSocketChannel::open).thenReturn(ch);

			Assertions.assertThrows(AlreadyBoundException.class, () -> RedirectTarget.start("/"));
		}
		Mockito.verify(ch).close();
	}

	@Test
	@DisplayName("tryBind(...) uses fallback port")
	public void testTryBind() throws IOException {
		var ch = Mockito.mock(ServerSocketChannel.class);
		Mockito.doThrow(new AlreadyBoundException()) // first attempt fails
				.doThrow(new AlreadyBoundException()) // second attempt fails
				.doReturn(ch) // third attempt succeeds
				.when(ch).bind(Mockito.any());

		Assertions.assertDoesNotThrow(() -> RedirectTarget.tryBind(ch, 17, 23, 42));

		Mockito.verify(ch).bind(new InetSocketAddress(RedirectTarget.LOOPBACK_ADDR, 42));
	}

	@Test
	@DisplayName("bind() to system-assigned port")
	public void testBindToSystemAssignedPort() throws IOException {
		var ch = Mockito.mock(ServerSocketChannel.class);

		RedirectTarget.tryBind(ch);

		Mockito.verify(ch).bind(Mockito.argThat(sa -> {
			if (sa instanceof InetSocketAddress) {
				var isa = (InetSocketAddress) sa;
				return isa.getPort() == 0;
			} else {
				return false;
			}
		}));
	}

	@Test
	@DisplayName("bind() to system-assigned port")
	public void testBindToFirstAvailablePort() throws IOException {
		var ch = Mockito.mock(ServerSocketChannel.class);
		Mockito.doThrow(new AlreadyBoundException()).when(ch).bind(Mockito.argThat(sa -> {
					if (sa instanceof InetSocketAddress) {
						var isa = (InetSocketAddress) sa;
						return isa.getPort() % 2 == 0;
					} else {
						return false;
					}
				}
		));

		Assertions.assertDoesNotThrow(() -> RedirectTarget.tryBind(ch, 8080, 8082, 8084, 7777));
		Mockito.verify(ch).bind(Mockito.argThat(sa -> {
			if (sa instanceof InetSocketAddress) {
				var isa = (InetSocketAddress) sa;
				return isa.getPort() == 7777;
			} else {
				return false;
			}
		}));
	}

	@Test
	@DisplayName("bind() fails if all ports taken")
	public void testBindFailsIfAllPortsTaken() throws IOException {
		var ch = Mockito.mock(ServerSocketChannel.class);
		Mockito.doThrow(new AlreadyBoundException()).when(ch).bind(Mockito.any());

		Assertions.assertThrows(AlreadyBoundException.class, () -> RedirectTarget.tryBind(ch, 8080, 8082, 8084));
	}

	@Test
	@DisplayName("http response 200 for valid redirect")
	public void testRedirectSuccess() throws IOException, InterruptedException, URISyntaxException, ExecutionException {
		try (var redirect = RedirectTarget.start("/")) {
			var baseUri = redirect.getRedirectUri();
			var query = "code=foobar&state=" + redirect.getCsrfToken();
			var uri = new URI(baseUri.getScheme(), baseUri.getAuthority(), baseUri.getPath(), query, baseUri.getFragment());

			var accessToken = receiveAsync(redirect);
			var request = HttpRequest.newBuilder(uri).GET().build();
			var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());

			Assertions.assertEquals(200, response.statusCode());
			Assertions.assertEquals("foobar", accessToken.get());
		}
	}

	@Test
	@DisplayName("http response 200 for failed login")
	public void testRedirectError() throws IOException, InterruptedException, URISyntaxException {
		try (var redirect = RedirectTarget.start("/")) {
			var baseUri = redirect.getRedirectUri();
			var query = "error=access_denied&state=" + redirect.getCsrfToken();
			var uri = new URI(baseUri.getScheme(), baseUri.getAuthority(), baseUri.getPath(), query, baseUri.getFragment());

			var accessToken = receiveAsync(redirect);
			var request = HttpRequest.newBuilder(uri).GET().build();
			var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());

			Assertions.assertEquals(200, response.statusCode());
			Assertions.assertThrows(ExecutionException.class, accessToken::get);
		}
	}

	@Test
	@DisplayName("http response 400 for missing code")
	public void testRedirectMissingCode() throws IOException, InterruptedException, URISyntaxException {
		try (var redirect = RedirectTarget.start("/")) {
			var baseUri = redirect.getRedirectUri();
			var query = "state=" + redirect.getCsrfToken();
			var uri = new URI(baseUri.getScheme(), baseUri.getAuthority(), baseUri.getPath(), query, baseUri.getFragment());

			var accessToken = receiveAsync(redirect);
			var request = HttpRequest.newBuilder(uri).GET().build();
			var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());

			Assertions.assertEquals(400, response.statusCode());
			Assertions.assertThrows(ExecutionException.class, accessToken::get);
		}
	}

	@DisplayName("http response 404 for wrong path")
	@ParameterizedTest
	@ValueSource(strings = {"/", "/invalid"})
	public void testRedirectNotFound(String invalidPath) throws IOException, InterruptedException, URISyntaxException {
		try (var redirect = RedirectTarget.start("/valid")) {
			var baseUri = redirect.getRedirectUri();
			var uri = new URI(baseUri.getScheme(), baseUri.getAuthority(), invalidPath, baseUri.getQuery(), baseUri.getFragment());

			var accessToken = receiveAsync(redirect);
			var request = HttpRequest.newBuilder(uri).GET().build();
			var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());

			Assertions.assertEquals(404, response.statusCode());
			Assertions.assertThrows(ExecutionException.class, accessToken::get);
		}
	}

	@DisplayName("http response 400 for missing of invalid state token")
	@ParameterizedTest
	@ValueSource(strings = {"code=correct", "state=wrong&code=correct"})
	public void testRedirectMissingStateToken(String query) throws IOException, InterruptedException, URISyntaxException {
		try (var redirect = RedirectTarget.start("/")) {
			var baseUri = redirect.getRedirectUri();
			var uri = new URI(baseUri.getScheme(), baseUri.getAuthority(), baseUri.getPath(), query, baseUri.getFragment());

			var accessToken = receiveAsync(redirect);
			var request = HttpRequest.newBuilder(uri).GET().build();
			var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());

			Assertions.assertEquals(400, response.statusCode());
			Assertions.assertThrows(ExecutionException.class, accessToken::get);
		}
	}

	@Test
	@DisplayName("http response 400 for malformed request")
	public void testRedirectMalformedRequest() throws IOException {
		try (var redirect = RedirectTarget.start("/")) {
			var port = redirect.getRedirectUri().getPort();
			var addr = new InetSocketAddress(InetAddress.getLoopbackAddress(), port);

			var accessToken = receiveAsync(redirect);
			var out = new ByteArrayOutputStream();
			try (var client = SocketChannel.open(addr); //
				 var writer = Channels.newWriter(client, StandardCharsets.UTF_8);
				 var in = Channels.newInputStream(client)) {
				writer.write("EHLO LOCALHOST\n"); // sic!
				writer.flush();
				in.transferTo(out);
			}
			var response = out.toString(StandardCharsets.UTF_8);

			Assertions.assertTrue(response.startsWith("HTTP/1.1 400"));
			Assertions.assertThrows(ExecutionException.class, accessToken::get);
		}
	}

	@Test
	@DisplayName("interrupting receive() causes ClosedByInterruptException")
	public void testInterrupt() throws IOException, InterruptedException {
		try (var redirect = RedirectTarget.start("/")) {
			var threadStarted = new CountDownLatch(1);
			var threadExited = new CountDownLatch(1);
			var exception = new AtomicReference<Exception>();
			var thread = new Thread(() -> {
				try {
					threadStarted.countDown();
					redirect.receive();
				} catch (IOException e) {
					exception.set(e);
				} finally {
					threadExited.countDown();
				}
			});
			thread.start();

			threadStarted.await();
			thread.interrupt();
			threadExited.await();

			Assertions.assertInstanceOf(ClosedByInterruptException.class, exception.get());
		}
	}

	@DisplayName("parse invalid request line")
	@ParameterizedTest(name = "parse {0}")
	@ValueSource(strings = {
			"GET /foo",
			"POST /foo HTTP/1.1",
			"GET !§$% /1.1",
	})
	public void testParseRequestLine(String requestLine) {
		Assertions.assertThrows(InvalidRequestException.class, () -> RedirectTarget.parseRequestLine(requestLine));
	}

	@DisplayName("parse valid request line")
	@ParameterizedTest(name = "parse {0}")
	@CsvSource({
			"GET /foo HTTP/1.1, /foo",
			"GET /foo/?foo=bar HTTP/1.1, /foo/?foo=bar",
			"GET http://example.com/foo/?foo=bar HTTP/1.1, http://example.com/foo/?foo=bar"
	})
	public void testParseRequestLine(String requestLine, String expectedResult) throws InvalidRequestException {
		var result = RedirectTarget.parseRequestLine(requestLine);

		Assertions.assertEquals(URI.create(expectedResult), result);
	}

	private CompletableFuture<String> receiveAsync(RedirectTarget redirectTarget) {
		return CompletableFuture.supplyAsync(() -> {
			try {
				return redirectTarget.receive();
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		});
	}

}