package io.github.coffeelibs.tinyoauth2client.http;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;

public class HttpResponseTest {

	@Test
	public void testEmpty() {
		var result = HttpResponse.empty(HttpResponse.Status.OK);
		Assertions.assertInstanceOf(HttpEmptyResponse.class, result);
	}

	@Test
	public void testHtml() {
		var result = HttpResponse.html(HttpResponse.Status.OK, "test");
		Assertions.assertInstanceOf(HttpHtmlResponse.class, result);
	}

	@Test
	public void testRedirect() {
		var result = HttpResponse.redirect(URI.create("http://google.com"));
		Assertions.assertInstanceOf(HttpRedirectResponse.class, result);
	}

}