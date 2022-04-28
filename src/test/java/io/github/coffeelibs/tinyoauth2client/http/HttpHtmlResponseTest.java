package io.github.coffeelibs.tinyoauth2client.http;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.CharArrayWriter;
import java.io.IOException;

public class HttpHtmlResponseTest {

	@Test
	public void testWrite() throws IOException {
		var body = "<html><body>Hello World</body></html>";
		var response = new HttpHtmlResponse(HttpResponse.Status.OK, body);
		var writer = new CharArrayWriter();

		response.write(writer);

		var str = writer.toString();
		Assertions.assertTrue(str.startsWith("HTTP/1.1 200 OK"));
		Assertions.assertTrue(str.contains("Content-Type: text/html; charset=UTF-8"));
		Assertions.assertTrue(str.contains("Content-Length: " + body.length()));
		Assertions.assertTrue(str.endsWith("<html><body>Hello World</body></html>\n"));
	}

}