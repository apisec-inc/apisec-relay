package ai.apisec.relay.apisec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Computes the APIsec endpointId.
 *
 * Rule (critical): endpointId = base64( method.toUpperCase() + ":" + path )
 * using UTF-8 and standard base64 with padding.
 *
 * Worked example: GET:/workshop/api/shop/orders/all encodes to
 * R0VUOi93b3Jrc2hvcC9hcGkvc2hvcC9vcmRlcnMvYWxs.
 *
 * The add-endpoints body uses the lowercase method; the scan body uses this
 * uppercase-derived endpointId. The two must not cross.
 */
public final class EndpointIds {

    public static String of(String method, String path) {
        String m = method == null ? "" : method.trim().toUpperCase();
        String p = path == null ? "" : path.trim();
        String raw = m + ":" + p;
        return Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    /** Stable dedup key, casing-normalized, independent of base64. */
    public static String key(String method, String path) {
        String m = method == null ? "" : method.trim().toUpperCase();
        String p = path == null ? "" : path.trim();
        return m + ":" + p;
    }

    private EndpointIds() {
    }
}
