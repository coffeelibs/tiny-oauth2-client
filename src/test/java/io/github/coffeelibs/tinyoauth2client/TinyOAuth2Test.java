package io.github.coffeelibs.tinyoauth2client;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;

public class TinyOAuth2Test {

    @Test
    @DisplayName("test fluent client builder")
    public void testBuilder() {
        var clientId = "foo";
        var tokenEndpoint = URI.create("bar");

        var client = TinyOAuth2.client(clientId).withTokenEndpoint(tokenEndpoint);

        Assertions.assertSame(clientId, client.clientId);
        Assertions.assertSame(tokenEndpoint, client.tokenEndpoint);
    }

}