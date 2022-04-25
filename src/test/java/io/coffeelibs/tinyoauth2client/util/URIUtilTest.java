package io.coffeelibs.tinyoauth2client.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.stream.Stream;

public class URIUtilTest {


	@DisplayName("parse query string")
	@ParameterizedTest(name = "parse {0}")
	@MethodSource("queryStrings")
	public void testParseQueryString(String query, Map<String, String> expectedResult) {
		var result = URIUtil.parseQueryString(query);

		Assertions.assertEquals(expectedResult, result);
	}

	public static Stream<Arguments> queryStrings() {
		return Stream.of(
				Arguments.of(null, Map.of()),
				Arguments.of("", Map.of()),
				Arguments.of("key1&key2&key3", Map.of("key1", "", "key2", "", "key3", "")),
				Arguments.of("key1=val1&key2=val2", Map.of("key1", "val1", "key2", "val2")),
				Arguments.of("key1=val1&key2=%26foo%3Dbar", Map.of("key1", "val1", "key2", "&foo=bar"))
		);
	}

}