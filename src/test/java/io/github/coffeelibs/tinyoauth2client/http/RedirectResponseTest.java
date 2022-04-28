package io.github.coffeelibs.tinyoauth2client.http;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.net.URI;

public class RedirectResponseTest {

	@Test
	public void testWrite() throws IOException {
		var response = new RedirectResponse(Response.Status.SEE_OTHER, URI.create("http://google.com"));
		var writer = new CharArrayWriter();

		response.write(writer);

		var str = writer.toString();
		Assertions.assertTrue(str.startsWith("HTTP/1.1 303 See Other"));
		Assertions.assertTrue(str.contains("Location: http://google.com"));
	}

}