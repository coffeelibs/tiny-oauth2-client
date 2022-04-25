package io.github.coffeelibs.tinyoauth2client.http;

import java.io.IOException;
import java.io.Writer;
import java.net.URI;

class HttpRedirectResponse implements HttpResponse {

	private final Status status;
	private URI target;

	public HttpRedirectResponse(Status status, URI target) {
		this.status = status;
		this.target = target;
	}

	@Override
	public void write(Writer writer) throws IOException {
		writer.write("HTTP/1.1 " + status.code + " " + status.reason + "\n");
		writer.write("Location: " + target + "\n");
		writer.write("Connection: Close\n");
		writer.write("\n");
	}

}
