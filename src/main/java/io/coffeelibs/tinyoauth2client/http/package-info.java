/**
 * A simple implementation for RFC 8252, Section 7.3:
 * <p>
 * We're spawning a local http server on a system-assigned high port
 * and use <code>http://127.0.0.1:{PORT}</code> as a redirect URI.
 */
package io.coffeelibs.tinyoauth2client.http;
