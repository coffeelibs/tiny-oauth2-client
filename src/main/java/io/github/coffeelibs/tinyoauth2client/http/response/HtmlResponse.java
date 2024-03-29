package io.github.coffeelibs.tinyoauth2client.http.response;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

class HtmlResponse implements Response {

    private final Status status;
    private final String body;

    public HtmlResponse(Status status, String body) {
        this.status = Objects.requireNonNull(status);
        this.body = Objects.requireNonNull(body);
    }

    @Override
    public void write(Writer writer) throws IOException {
        writer.write("HTTP/1.1 " + status.code + " " + status.reason + "\n");
        writer.write("Content-Type: text/html; charset=UTF-8\n");
        writer.write("Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\n");
        writer.write("Connection: Close\n");
        writer.write("\n");
        writer.write(body);
        writer.write("\n");
    }
}
