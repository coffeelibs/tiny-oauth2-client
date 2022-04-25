[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=coverage)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=coffeelibs_tiny-oauth2-client&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=coffeelibs_tiny-oauth2-client)

# Tiny OAuth2 Client

This is a minimal zero-dependency implementation of the [RFC 8252 OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252), relying
on [Loopback Interface Redirection](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3) (i.e. no need to register a private-use URI scheme) with full
support for [PKCE](https://datatracker.ietf.org/doc/html/rfc8252#section-8.1) and [CSRF Protection](https://datatracker.ietf.org/doc/html/rfc8252#section-8.9).

## Usage

```java
// this library will just to the Authorization Flow:
String tokenResponse = AuthFlow.asClient("oauth-client-id")
        .authorize(URI.create("https://login.example.com/oauth2/authorize"), uri -> System.out.println("Please login on " + uri))
        .getAccessToken(URI.create("https://login.example.com/oauth2/token"));

// from this point onwards, please proceed with the JSON/JWT parser of your choice: 
String bearerToken = parse(tokenResponse);
```

## Customization

The `authorize(...)` method optionally allows you to specify:

* custom [scopes](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3)
* custom port(s) of your redirect_uri (default will be a system-assigned ephemeral port)
* a custom path for your redirect_uri (default is a random path)

## Why this library?

* Often you just need to authorize your client and nothing more. Most OAuth2 libraries try to do a lot more
* Nano-tiny-minuscule attack surface, since this doesn't contain any JOSE/JWT signature code, nor a fully-fleged web server
* Focus is strictly on the authorization flow. Use any library for dealing with the tokens, you like.
* Modular jar, exposing only one single public API. No need to read docs, you can't do anything wrong.