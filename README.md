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

You begin building an OAuth 2.0 Client via the fluent API:

```java
var oauthClient = TinyOAuth2.client("oauth-client-id") // The client identifier
		.withTokenEndpoint(URI.create("https://login.example.com/oauth2/token")) // The token endpoint
		.withRequestTimeout(Duration.ofSeconds(10)) // optional
        // ...
```

Next, continue with a specific grant type by invoking `.authorizationCodeGrant(...)` or `.clientCredentialsGrant(...)` (more may be added eventually).

This library requires you to provide an instance of [`java.net.http.HttpClient`](https://docs.oracle.com/en/java/javase/11/docs/api/java.net.http/java/net/http/HttpClient.html).
This allows you to configure it to your needs, e.g. by applying proxy settings:

```java
var httpClient = HttpClient.newBuilder()
    .proxy(ProxySelector.of(InetSocketAddress.createUnresolved("https:\\example.com",1337)))
    .build();
```

### Authorization Code Grant
Usually, you would want to use the [Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) type to obtain access tokens.
Configure your Authorization Server to allow `http://127.0.0.1/*` as a redirect target and look up the authorization endpoint:

```java
// this library will just perform the Authorization Flow:
var httpResponse = oauthClient.authorizationCodeGrant(URI.create("https://login.example.com/oauth2/authorize"))
		.authorize(httpClient, uri -> System.out.println("Please login on " + uri));
```

If your authorization server doesn't allow wildcards, you can also configure a fixed path (and even port) via e.g. `setRedirectPath("/callback")` and `setRedirectPorts(8080)` before calling `authorize(...)`.

### Client Credentials Grant
Alternatively, if your client shall act on behalf of a service account, use the [Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) type,
which allows the client to authenticate directly without further user interaction: 

```java
var httpResponse = oauthClient.clientCredentialsGrant(UTF_8, "client secret")
        .authorize(httpClient);
```

### Parsing the Response
For maximum flexibility and minimal attack surface, this library does not include or depend on a specific parser. Instead, use a JSON or JWT parser of your choice to parse the Authorization Server's response:

```java
if (httpResponse.statusCode() == 200) {
		var jsonString = httpResponse.body()
		var bearerToken = parseJson(jsonString).get("access_token");
		// ...
}
```

## Why this library?

* Often you just need to authorize your client and nothing more. Most OAuth2 libraries try to do a lot more
* Nano-tiny-minuscule attack surface, since this doesn't contain any JOSE/JWT signature code, nor a fully-fledged web server
* Focus is strictly on the authorization flow. Use any library for dealing with the tokens, you like.
* Modular jar, exposing only one single public API. No need to read docs, you can't do anything wrong.