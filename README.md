[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=coverage)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)

# Tiny OAuth2 Client

This is a minimal zero-dependency implementation of the [RFC 8252 OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252), relying
on [Loopback Interface Redirection](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3) (i.e. no need to register a private-use URI scheme) with full
support for [PKCE](https://datatracker.ietf.org/doc/html/rfc8252#section-8.1) and [CSRF Protection](https://datatracker.ietf.org/doc/html/rfc8252#section-8.9).

## Requirements

* Java 11+
* Ideally some JSON or JWT parser of your choice

## Usage

Configure your authorization server to allow `http://127.0.0.1/*` as a redirect target and look up these configuration values:

* client identifier
* token endpoint
* authorization endpoint

```java
// this library will just perform the Authorization Flow:
var httpResponse = TinyOAuth2.client("oauth-client-id")
		.withTokenEndpoint(URI.create("https://login.example.com/oauth2/token"))
		.authFlow(URI.create("https://login.example.com/oauth2/authorize"))
		.authorize(uri -> System.out.println("Please login on " + uri));

// from this point onwards, please proceed with the JSON/JWT parser of your choice:
if (httpResponse.statusCode() == 200) {
	var jsonString = httpResponse.body()
	var bearerToken = parseJson(jsonString).get("access_token");
	// ...
}
```

If your authorization server doesn't allow wildcards, you can also configure a fixed path (and even port) via e.g. `setRedirectPath("/callback")` and `setRedirectPorts(8080)`.

## Why this library?

* Often you just need to authorize your client and nothing more. Most OAuth2 libraries try to do a lot more
* Nano-tiny-minuscule attack surface, since this doesn't contain any JOSE/JWT signature code, nor a fully-fledged web server
* Focus is strictly on the authorization flow. Use any library for dealing with the tokens, you like.
* Modular jar, exposing only one single public API. No need to read docs, you can't do anything wrong.