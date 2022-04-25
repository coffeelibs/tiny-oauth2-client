package io.coffeelibs.tinyoauth2client.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

public class RandomUtilTest {

	@ParameterizedTest
	@ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	public void testGetRandomToken(int len) {
		var token = RandomUtil.randomToken(len);
		Assertions.assertEquals(len, token.length());
	}

	@Test
	public void testTokensDontRepeat() {
		long uniqueElements = Stream.generate(() -> RandomUtil.randomToken(16)).limit(100).distinct().count();
		Assertions.assertEquals(100, uniqueElements);
	}

}