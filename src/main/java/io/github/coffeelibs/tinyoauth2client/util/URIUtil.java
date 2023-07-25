package io.github.coffeelibs.tinyoauth2client.util;

import org.jetbrains.annotations.Nullable;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class URIUtil {

    private URIUtil() {
    }

    /**
     * Splits a query string into key-value pairs. Behaviour for duplicate keys is undefined as this is not required in the scope of this project.
     * If a value is not specified for a key, the key will be mapped to an empty string.
     *
     * @param rawQuery The unparsed query string
     * @return A map of key-value pairs
     */
    public static Map<String, String> parseQueryString(@Nullable String rawQuery) {
        if (rawQuery == null) {
            return Map.of();
        }
        return Pattern.compile("&").splitAsStream(rawQuery).filter(Predicate.not(String::isEmpty)).map(element -> {
            var sep = element.indexOf("=");
            if (sep == -1) {
                var key = URLDecoder.decode(element, StandardCharsets.UTF_8);
                return Map.entry(key, "");
            } else {
                var key = URLDecoder.decode(element.substring(0, sep), StandardCharsets.UTF_8);
                var val = URLDecoder.decode(element.substring(sep + 1), StandardCharsets.UTF_8);
                return Map.entry(key, val);
            }
        }).collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * Builds a urlencoded query string from the given {@code queryParams}. Percent encoding will be applied to each
     * key and value.
     * <p>
     * The result can either be appended to an {@link java.net.URI} or used in
     * {@code application/x-www-form-urlencoded}-encoded request bodies.
     *
     * @param queryParams key-value pairs
     * @return A query string
     */
    public static String buildQueryString(Map<String, String> queryParams) {
        return queryParams.entrySet().stream().map(entry -> {
            var encodedKey = URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8);
            var encodedValue = URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8);
            return encodedKey + (encodedValue.isBlank() ? "" : "=" + encodedValue);
        }).collect(Collectors.joining("&"));
    }

}
