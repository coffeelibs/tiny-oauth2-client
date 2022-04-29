package io.github.coffeelibs.tinyoauth2client.http;

import java.io.IOException;
import java.io.Writer;
import java.util.Objects;

class EmptyResponse implements Response {

	private final Status status;

	public EmptyResponse(Response.Status status) {
		this.status = Objects.requireNonNull(status);
	}

	@Override
	public void write(Writer writer) throws IOException {
		writer.write("HTTP/1.1 " + status.code + " " + status.reason + "\n");
		writer.write("Connection: Close\n");
		writer.write("\n");
	}

}
