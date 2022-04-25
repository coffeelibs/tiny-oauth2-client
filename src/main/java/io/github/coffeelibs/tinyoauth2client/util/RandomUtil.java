package io.github.coffeelibs.tinyoauth2client.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class RandomUtil {

	private static final SecureRandom CSPRNG;

	static {
		try {
			CSPRNG = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			// "Every implementation of the Java platform is required to support at least one strong SecureRandom implementation."
			throw new AssertionError(e);
		}
	}

	private RandomUtil() {
	}

	/**
	 * Generate an URL-safe random string.
	 *
	 * @param len Desired length of the string
	 * @return A random string
	 */
	public static String randomToken(int len) {
		int numBytes = ((len + 3) / 4) * 3;
		var bytes = randomBytes(numBytes);
		var str = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		return str.substring(0, len);
	}

	/**
	 * Generate {@code len} random bytes
	 * @param len Desired number of bytes
	 * @return A random byte array
	 */
	public static byte[] randomBytes(int len) {
		byte[] bytes = new byte[len];
		CSPRNG.nextBytes(bytes);
		return bytes;
	}
}
