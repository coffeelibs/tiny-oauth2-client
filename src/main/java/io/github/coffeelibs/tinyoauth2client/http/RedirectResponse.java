package io.github.coffeelibs.tinyoauth2client.http;

import java.io.IOException;
import java.io.Writer;
import java.net.URI;
import java.util.Objects;

class RedirectResponse implements Response {

	private final Status status;
	private URI target;

	public RedirectResponse(Status status, URI target) {
		this.status = Objects.requireNonNull(status);
		this.target = Objects.requireNonNull(target);
	}

	@Override
	public void write(Writer writer) throws IOException {
		writer.write("HTTP/1.1 " + status.code + " " + status.reason + "\n");
		writer.write("Location: " + target + "\n");
		writer.write("Connection: Close\n");
		writer.write("\n");
	}

}
