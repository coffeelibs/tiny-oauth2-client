package io.github.coffeelibs.tinyoauth2client.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

public class URIUtilTest {

    @Test
    @DisplayName("parse null query string")
    public void testParseQueryStringNull() {
        var result = URIUtil.parseQueryString(null);

        Assertions.assertTrue(result.isEmpty());
    }


    @DisplayName("parse query string")
    @ParameterizedTest(name = "parse \"{0}\"")
    @MethodSource("queryStrings")
    public void testParseQueryString(String query, Map<String, String> expectedResult) {
        var result = URIUtil.parseQueryString(query);

        Assertions.assertEquals(expectedResult, result);
    }

    @DisplayName("build query string")
    @ParameterizedTest(name = "build \"{0}\"")
    @MethodSource("queryStrings")
    public void testBuildQueryString(String expectedResult, Map<String, String> queryParams) {
        var result = URIUtil.buildQueryString(queryParams);

        Assertions.assertEquals(expectedResult, result);
    }

    public static Stream<Arguments> queryStrings() {
        // use tree map for deterministic order in #testBuildQueryString(...)
        return Stream.of(
                Arguments.of("", Map.of()),
                Arguments.of("key1&key2&key3", new TreeMap<>(Map.of("key1", "", "key2", "", "key3", ""))),
                Arguments.of("key1=val1&key2=val2", new TreeMap<>(Map.of("key1", "val1", "key2", "val2"))),
                Arguments.of("key1=val1&key2=%26foo%3Dbar", new TreeMap<>(Map.of("key1", "val1", "key2", "&foo=bar")))
        );
    }

}