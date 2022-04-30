package io.github.coffeelibs.tinyoauth2client.http.response;

import io.github.coffeelibs.tinyoauth2client.http.response.RedirectResponse;
import io.github.coffeelibs.tinyoauth2client.http.response.Response;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.net.URI;

public class RedirectResponseTest {

	@Test
	@DisplayName("constructor throws NPE when status is null")
	public void testNullBody() {
		Assertions.assertThrows(NullPointerException.class, () -> new RedirectResponse(Response.Status.SEE_OTHER, null));
	}

	@Test
	@DisplayName("constructor throws NPE when status is null")
	public void testNullStatus() {
		var target = URI.create("http://google.com");
		Assertions.assertThrows(NullPointerException.class, () -> new RedirectResponse(null, target));
	}

	@Test
	@DisplayName("write() writes expected response")
	public void testWrite() throws IOException {
		var response = new RedirectResponse(Response.Status.SEE_OTHER, URI.create("http://google.com"));
		var writer = new CharArrayWriter();

		response.write(writer);

		var str = writer.toString();
		Assertions.assertTrue(str.startsWith("HTTP/1.1 303 See Other"));
		Assertions.assertTrue(str.contains("Location: http://google.com"));
	}

}