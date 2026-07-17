package ai.apisec.relay.testset;

import java.util.regex.Pattern;

/**
 * Detects concrete (non-templatized) values in a staged request path so the
 * operator can be warned and offered a one-click templatize before submit (A10).
 *
 * "Concrete" means a value that looks like a specific instance rather than a
 * parameter placeholder: a bare numeric path segment (/orders/123) or a query
 * value after '=' that is not already a {name} template (?id=5, ?report_id=2).
 *
 * Templatizing rewrites those to {name} so APIsec stores one parameterized
 * endpoint instead of polluting the project with a row per concrete value.
 */
public final class PathTemplatizer {

    // A path segment that is entirely digits, e.g. "123".
    private static final Pattern NUMERIC_SEGMENT = Pattern.compile("^\\d+$");
    // A query value that is already a {name} template.
    private static final Pattern TEMPLATE_VALUE = Pattern.compile("^\\{[^}]+}$");

    /** True if the path (with optional query) contains any concrete value. */
    public static boolean hasConcreteValues(String path) {
        if (path == null || path.isBlank()) {
            return false;
        }
        String[] split = splitPathQuery(path);
        return concreteInPath(split[0]) || concreteInQuery(split[1]);
    }

    /**
     * Rewrites concrete values to {name} templates.
     *  - numeric path segment  /orders/123        -> /orders/{order_id} using the
     *    preceding segment as the hint, else {id}.
     *  - query value           ?report_id=2       -> ?report_id={report_id}
     *    (the key drives the placeholder name).
     */
    public static String templatize(String path) {
        if (path == null || path.isBlank()) {
            return path;
        }
        String[] split = splitPathQuery(path);
        String templPath = templatizePath(split[0]);
        String templQuery = templatizeQuery(split[1]);
        return templQuery == null ? templPath : templPath + "?" + templQuery;
    }

    private static String[] splitPathQuery(String path) {
        int q = path.indexOf('?');
        if (q < 0) {
            return new String[]{path, null};
        }
        return new String[]{path.substring(0, q), path.substring(q + 1)};
    }

    private static boolean concreteInPath(String rawPath) {
        if (rawPath == null) {
            return false;
        }
        for (String seg : rawPath.split("/")) {
            if (NUMERIC_SEGMENT.matcher(seg).matches()) {
                return true;
            }
        }
        return false;
    }

    private static boolean concreteInQuery(String query) {
        if (query == null || query.isBlank()) {
            return false;
        }
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq >= 0 && eq < pair.length() - 1) {
                String value = pair.substring(eq + 1);
                if (!value.isBlank() && !TEMPLATE_VALUE.matcher(value).matches()) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String templatizePath(String rawPath) {
        if (rawPath == null) {
            return null;
        }
        String[] segs = rawPath.split("/", -1);
        for (int i = 0; i < segs.length; i++) {
            if (NUMERIC_SEGMENT.matcher(segs[i]).matches()) {
                String hint = i > 0 && !segs[i - 1].isBlank() ? singular(segs[i - 1]) + "_id" : "id";
                segs[i] = "{" + hint + "}";
            }
        }
        return String.join("/", segs);
    }

    private static String templatizeQuery(String query) {
        if (query == null) {
            return null;
        }
        String[] pairs = query.split("&");
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) {
                out.append('&');
            }
            String pair = pairs[i];
            int eq = pair.indexOf('=');
            if (eq >= 0 && eq < pair.length() - 1) {
                String key = pair.substring(0, eq);
                String value = pair.substring(eq + 1);
                if (!value.isBlank() && !TEMPLATE_VALUE.matcher(value).matches()) {
                    String name = key.isBlank() ? "value" : key;
                    out.append(key).append("={").append(name).append('}');
                    continue;
                }
            }
            out.append(pair);
        }
        return out.toString();
    }

    private static String singular(String s) {
        if (s.length() > 1 && s.endsWith("s")) {
            return s.substring(0, s.length() - 1);
        }
        return s;
    }

    private PathTemplatizer() {
    }
}
