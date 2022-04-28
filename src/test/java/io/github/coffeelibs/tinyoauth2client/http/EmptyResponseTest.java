package io.github.coffeelibs.tinyoauth2client.http;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.CharArrayWriter;
import java.io.IOException;

public class EmptyResponseTest {

	@Test
	public void testWrite() throws IOException {
		var html = "<html><body>Hello World</body></html>";
		var response = new HtmlResponse(Response.Status.OK, html);
		var writer = new CharArrayWriter();

		response.write(writer);

		var str = writer.toString();
		Assertions.assertTrue(str.startsWith("HTTP/1.1 200 OK"));
		Assertions.assertTrue(str.contains("Content-Type: text/html"));
		Assertions.assertTrue(str.contains("Content-Length: " + html.length()));
		Assertions.assertTrue(str.endsWith(html + "\n"));
	}

}