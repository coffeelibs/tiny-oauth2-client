package io.github.coffeelibs.tinyoauth2client.http;

public class InvalidRequestException extends Exception {
	public final Response suggestedResponse;

	public InvalidRequestException(Response suggestedResponse) {
		this.suggestedResponse = suggestedResponse;
	}

}
