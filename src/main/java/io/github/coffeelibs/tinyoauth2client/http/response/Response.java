package io.github.coffeelibs.tinyoauth2client.http.response;

import org.jetbrains.annotations.Contract;

import java.io.IOException;
import java.io.Writer;
import java.net.URI;

public interface Response {

	void write(Writer writer) throws IOException;

	/**
	 *
	 * @param status
	 * @return
	 */
	@Contract("!null -> new")
	static Response empty(Status status) {
		return new EmptyResponse(status);
	}

	/**
	 *
	 * @param status
	 * @param body content served with {@code Content-Type: text/html; charset=UTF-8}
	 * @return A new response
	 */
	@Contract("!null, !null -> new")
	static Response html(Status status, String body) {
		return new HtmlResponse(status, body);
	}

	/**
	 *
	 * @param target URI of page to show
	 * @return
	 */
	@Contract("!null -> new")
	static Response redirect(URI target) {
		return new RedirectResponse(Status.SEE_OTHER, target);
	}

	enum Status {
		OK(200, "OK"),
		SEE_OTHER(303, "See Other"),
		BAD_REQUEST(400, "Bad Request"),
		NOT_FOUND(404, "Not Found"),
		METHOD_NOT_ALLOWED(405, "Method not Allowed");

		public final int code;
		public final String reason;

		Status(int code, String reason) {
			this.code = code;
			this.reason = reason;
		}
	}

}
