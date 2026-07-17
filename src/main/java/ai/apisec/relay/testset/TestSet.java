package ai.apisec.relay.testset;

import ai.apisec.relay.apisec.EndpointIds;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An ordered, deduplicated set of requests staged from Burp for submission to
 * APIsec. Dedup is by EndpointIds.key (upper(method) + ":" + path), so the same
 * endpoint staged from proxy history and from Repeater collapses to one row.
 *
 * The path on a StagedRequest is mutable so the operator can templatize concrete
 * values (/orders/123 -> /orders/{order_id}) before submit; re-keying after an
 * edit is the panel's responsibility via reindex().
 */
public final class TestSet {

    private String name;
    private final Map<String, StagedRequest> byKey = new LinkedHashMap<>();

    public TestSet() {
        this("Test set");
    }

    public TestSet(String name) {
        setName(name);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Test set name cannot be blank.");
        }
        this.name = name.trim();
    }

    @Override
    public String toString() {
        return name;
    }

    /** Returns true if added, false if a row with the same key already existed. */
    public boolean add(StagedRequest req) {
        if (req == null) {
            return false;
        }
        String key = EndpointIds.key(req.getMethod(), req.getPath());
        if (byKey.containsKey(key)) {
            return false;
        }
        byKey.put(key, req);
        return true;
    }

    public void remove(StagedRequest req) {
        if (req == null) {
            return;
        }
        byKey.values().remove(req);
    }

    public void clear() {
        byKey.clear();
    }

    public int size() {
        return byKey.size();
    }

    public List<StagedRequest> items() {
        return new ArrayList<>(byKey.values());
    }

    /**
     * Rebuilds the dedup index from current row state. Call after a path edit so
     * two rows that now collide are merged (last edit wins, order preserved).
     */
    public void reindex() {
        List<StagedRequest> current = new ArrayList<>(byKey.values());
        byKey.clear();
        for (StagedRequest r : current) {
            byKey.put(EndpointIds.key(r.getMethod(), r.getPath()), r);
        }
    }

    /** A single staged request. method/origin are fixed; path/body are editable. */
    public static final class StagedRequest {
        private final String method;
        private String path;
        private String body;
        private final String origin;

        public StagedRequest(String method, String path, String body, String origin) {
            this.method = method == null ? "" : method;
            this.path = path == null ? "" : path;
            this.body = body == null ? "" : body;
            this.origin = origin == null ? "" : origin;
        }

        public String getMethod() {
            return method;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path == null ? "" : path;
        }

        public String getBody() {
            return body;
        }

        public String getOrigin() {
            return origin;
        }

        public String endpointId() {
            return EndpointIds.of(method, path);
        }
    }
}
