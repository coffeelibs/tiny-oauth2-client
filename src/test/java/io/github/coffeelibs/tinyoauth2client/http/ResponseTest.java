package io.github.coffeelibs.tinyoauth2client.http;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;

public class ResponseTest {

	@Test
	public void testEmpty() {
		var result = Response.empty(Response.Status.OK);
		Assertions.assertInstanceOf(EmptyResponse.class, result);
	}

	@Test
	public void testHtml() {
		var result = Response.html(Response.Status.OK, "test");
		Assertions.assertInstanceOf(HtmlResponse.class, result);
	}

	@Test
	public void testRedirect() {
		var result = Response.redirect(URI.create("http://google.com"));
		Assertions.assertInstanceOf(RedirectResponse.class, result);
	}

}