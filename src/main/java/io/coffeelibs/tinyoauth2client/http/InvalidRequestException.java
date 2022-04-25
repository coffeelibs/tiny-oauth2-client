package io.coffeelibs.tinyoauth2client.http;

public class InvalidRequestException extends Exception {
	public final HttpResponse suggestedResponse;

	public InvalidRequestException(HttpResponse suggestedResponse) {
		this.suggestedResponse = suggestedResponse;
	}

}
