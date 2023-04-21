package io.github.coffeelibs.tinyoauth2client.http.response;

import io.github.coffeelibs.tinyoauth2client.http.response.EmptyResponse;
import io.github.coffeelibs.tinyoauth2client.http.response.Response;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.CharArrayWriter;
import java.io.IOException;

public class EmptyResponseTest {

    @Test
    @DisplayName("constructor throws NPE when status is null")
    public void testNullStatus() {
        Assertions.assertThrows(NullPointerException.class, () -> new EmptyResponse(null));
    }

    @Test
    @DisplayName("write() writes expected response")
    public void testWrite() throws IOException {
        var response = new EmptyResponse(Response.Status.OK);
        var writer = new CharArrayWriter();

        response.write(writer);

        var str = writer.toString();
        Assertions.assertTrue(str.startsWith("HTTP/1.1 200 OK"));
    }

}