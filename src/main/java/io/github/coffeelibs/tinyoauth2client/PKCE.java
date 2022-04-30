package io.github.coffeelibs.tinyoauth2client;

import io.github.coffeelibs.tinyoauth2client.util.RandomUtil;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7636">RFC 7636</a>
 */
class PKCE {

	public static final String METHOD = "S256";

	private final String challenge;
	private final String verifier;

	public PKCE() {
		// https://datatracker.ietf.org/doc/html/rfc7636#section-4
		this.verifier = RandomUtil.randomToken(43);
		this.challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(verifier.getBytes(StandardCharsets.US_ASCII)));
	}

	public String getChallenge() {
		return challenge;
	}

	public String getVerifier() {
		return verifier;
	}

	private static byte[] sha256(byte[] input) {
		try {
			var digest = MessageDigest.getInstance("SHA-256");
			return digest.digest(input);
		} catch (NoSuchAlgorithmException e) {
			// "Every implementation of the JDK 11 platform must support the specified algorithms [...]: SHA-256"
			// see https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#security-algorithm-implementation-requirements
			throw new AssertionError(e);
		}
	}

}
