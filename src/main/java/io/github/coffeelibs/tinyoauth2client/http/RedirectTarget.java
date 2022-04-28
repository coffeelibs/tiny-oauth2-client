package io.github.coffeelibs.tinyoauth2client.http;

import io.github.coffeelibs.tinyoauth2client.util.RandomUtil;
import io.github.coffeelibs.tinyoauth2client.util.URIUtil;
import org.jetbrains.annotations.VisibleForTesting;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.channels.AlreadyBoundException;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * A TCP connector to deal with the redirect response. We only listen for the expected response,
 * discarding everything else. While this looks like reinventing the wheel, it avoids all the
 * attack surface from a fully-fledged http server as we don't need features such as charsets,
 * compression, request body handlers, transfer encoding, protocol upgrades, request methods,
 * http headers, ...
 * <p>
 * Futhermore, since you can't get a (valid) certificate for localhost, we don't need to deal with TLS,
 * i.e. HTTP/2 and later can't be used, so all we really need is a simple text-based parser of the HTTP
 * request line.
 */
public class RedirectTarget implements Closeable {

	private static final InetAddress LOOPBACK_ADDR = InetAddress.getLoopbackAddress();

	private final ServerSocketChannel serverChannel;
	private final String path;
	private final String csrfToken;

	private Response successResponse = Response.html(Response.Status.OK, "<html><body>Success</body></html>");
	private Response errorResponse = Response.html(Response.Status.BAD_REQUEST, "<html><body>Error</body></html>");

	private RedirectTarget(ServerSocketChannel serverChannel, String path) {
		this.serverChannel = serverChannel;
		this.path = path;
		this.csrfToken = RandomUtil.randomToken(16);
	}

	/**
	 * Spawns a server on one of the given ports, ready to accept connections.
	 * <p>
	 * If one or many {@code ports} are specified, an attempt is made to bind to the first available port. If omitted,
	 * a system-assigned port is used.
	 *
	 * @param path  The path to listen on. All other requests will be considered invalid
	 * @param ports TCP port numbers
	 * @return The running server
	 * @throws IOException If an I/O error occurs
	 */
	public static RedirectTarget start(String path, int... ports) throws IOException {
		if (!path.startsWith("/")) {
			throw new IllegalArgumentException("Path needs to be absolute");
		}
		ServerSocketChannel ch = null;
		boolean success = false;
		try {
			ch = ServerSocketChannel.open();
			tryBind(ch, ports);
			ch.configureBlocking(true);
			success = true;
			return new RedirectTarget(ch, path);
		} finally {
			if (!success && ch != null) {
				ch.close();
			}
		}
	}

	@VisibleForTesting
	static void tryBind(ServerSocketChannel ch, int... ports) throws IOException {
		if (ports.length == 0) {
			ch.bind(new InetSocketAddress(LOOPBACK_ADDR, 0));
		} else {
			for (int port : ports) {
				try {
					ch.bind(new InetSocketAddress(LOOPBACK_ADDR, port));
					return;
				} catch (AlreadyBoundException e) {
					// try next
				}
			}
			throw new AlreadyBoundException();
		}
	}

	public void setSuccessResponse(Response successResponse) {
		this.successResponse = successResponse;
	}

	public void setErrorResponse(Response errorResponse) {
		this.errorResponse = errorResponse;
	}

	public URI getRedirectUri() {
		try {
			// use 127.0.0.1, not "localhost", see https://datatracker.ietf.org/doc/html/rfc8252#section-8.3
			return new URI("http", null, LOOPBACK_ADDR.getHostAddress(), serverChannel.socket().getLocalPort(), path, null, null);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public String getCsrfToken() {
		return csrfToken;
	}

	/**
	 * Waits for the first HTTP request made on {@link #getRedirectUri() the redirect URI}, discards everything but the
	 * request URI and extracts the response parameters from its query string.
	 *
	 * @return The authorization code
	 * @throws IOException In case of I/O errors when communicating with the user agent
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2">RFC 6749, 4.1.2. Authorization Response</a>
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1">RFC 6749, 4.1.2.1 Error Response</a>
	 */
	public String receive() throws IOException {
		var client = serverChannel.accept();
		try (var reader = new BufferedReader(Channels.newReader(client, StandardCharsets.US_ASCII));
			 var writer = Channels.newWriter(client, StandardCharsets.UTF_8)) {
			var requestLine = reader.readLine();
			final URI requestUri;
			try {
				requestUri = parseRequestLine(requestLine);
			} catch (InvalidRequestException e) {
				e.suggestedResponse.write(writer);
				throw new IOException("Unparseable Request", e);
			}
			if (!Path.of(path).equals(Path.of(requestUri.getPath()))) {
				Response.empty(Response.Status.NOT_FOUND).write(writer);
				throw new IOException("Requested invalid path " + requestUri);
			}

			var params = URIUtil.parseQueryString(requestUri.getRawQuery());
			if (!csrfToken.equals(params.get("state"))) {
				Response.empty(Response.Status.BAD_REQUEST).write(writer);
				throw new IOException("Missing or invalid state token");
			} else if (params.containsKey("error")) {
//				var html = "<html><body>" + params.get("error") + "</body></html>";
//				Response.html(Response.Status.OK, html).write(writer);
				errorResponse.write(writer); // TODO insert error code?
				throw new IOException("Authorization failed"); // TODO more specific exception containing the error code
			} else if (params.containsKey("code")) {
				successResponse.write(writer);
				return params.get("code");
			} else {
				Response.empty(Response.Status.BAD_REQUEST).write(writer);
				throw new IOException("Missing authorization code");
			}
		}
	}

	/**
	 * Attempts to parse the given request line and extract the request URI.
	 *
	 * @param requestLine A HTTP request line as specified in <a href="https://datatracker.ietf.org/doc/html/rfc2616#section-5.1">RFC 2616 Section 5.1</a>
	 * @return The request URI
	 * @throws InvalidRequestException Thrown when the request line is malformed
	 */
	@VisibleForTesting
	static URI parseRequestLine(String requestLine) throws InvalidRequestException {
		var words = requestLine.split(" ");
		if (words.length < 3) {
			throw new InvalidRequestException(Response.empty(Response.Status.BAD_REQUEST));
		}
		var method = words[0];
		if (!"GET".equals(method)) {
			throw new InvalidRequestException(Response.empty(Response.Status.METHOD_NOT_ALLOWED));
		}
		try {
			return new URI(words[1]);
		} catch (URISyntaxException e) {
			throw new InvalidRequestException(Response.empty(Response.Status.BAD_REQUEST));
		}
	}

	/**
	 * Shuts down this server and releases the port it has been bound to.
	 *
	 * @throws IOException If an I/O error occurs
	 */
	@Override
	public void close() throws IOException {
		serverChannel.close();
	}

}
