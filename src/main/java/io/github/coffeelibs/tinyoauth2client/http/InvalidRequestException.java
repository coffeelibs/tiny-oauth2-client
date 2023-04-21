package io.github.coffeelibs.tinyoauth2client.http;

import io.github.coffeelibs.tinyoauth2client.http.response.Response;

public class InvalidRequestException extends Exception {
    public final Response suggestedResponse;

    public InvalidRequestException(Response suggestedResponse) {
        this.suggestedResponse = suggestedResponse;
    }

}
