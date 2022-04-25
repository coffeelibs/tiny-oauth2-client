package io.coffeelibs.tinyoauth2client.http;

import java.io.IOException;
import java.io.Writer;

class HttpEmptyResponse implements HttpResponse {

	private final Status status;

	public HttpEmptyResponse(HttpResponse.Status status) {
		this.status = status;
	}

	@Override
	public void write(Writer writer) throws IOException {
		writer.write("HTTP/1.1 " + status.code + " " + status.reason + "\n");
		writer.write("Connection: Close\n");
		writer.write("\n");
	}

}
