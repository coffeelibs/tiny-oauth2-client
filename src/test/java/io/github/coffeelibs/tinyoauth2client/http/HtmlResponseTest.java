package io.github.coffeelibs.tinyoauth2client.http;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.CharArrayWriter;
import java.io.IOException;

public class HtmlResponseTest {

	@Test
	@DisplayName("constructor throws NPE when status is null")
	public void testNullBody() {
		Assertions.assertThrows(NullPointerException.class, () -> new HtmlResponse(Response.Status.OK, null));
	}

	@Test
	@DisplayName("constructor throws NPE when status is null")
	public void testNullStatus() {
		Assertions.assertThrows(NullPointerException.class, () -> new HtmlResponse(null, ""));
	}

	@Test
	@DisplayName("write() writes expected response")
	public void testWrite() throws IOException {
		var body = "<html><body>Hello World</body></html>";
		var response = new HtmlResponse(Response.Status.OK, body);
		var writer = new CharArrayWriter();

		response.write(writer);

		var str = writer.toString();
		Assertions.assertTrue(str.startsWith("HTTP/1.1 200 OK"));
		Assertions.assertTrue(str.contains("Content-Type: text/html; charset=UTF-8"));
		Assertions.assertTrue(str.contains("Content-Length: " + body.length()));
		Assertions.assertTrue(str.endsWith("<html><body>Hello World</body></html>\n"));
	}

}