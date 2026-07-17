package ai.apisec.relay.apisec.model;

import java.util.List;

/**
 * GET /v1/applications/{appId}/instances/{instanceId}/endpoints?include=metadata&slim=true
 *
 * The real response nests endpoints under endpointGroups[].endpoints[], not a
 * flat endpoints[]. Each endpoint carries id (the base64 endpointId used for
 * dedup), path, and method. Partial by design; unknown fields are ignored.
 */
public final class EndpointModels {

    public static final class EndpointsResponse {
        public Metadata metadata;
        public List<EndpointGroup> endpointGroups;
    }

    public static final class Metadata {
        public Integer numEndpoints;
    }

    public static final class EndpointGroup {
        public String groupId;
        public String name;
        public List<EndpointItem> endpoints;
    }

    public static final class EndpointItem {
        public String id;      // base64 endpointId, e.g. R0VUOi93b3Jrc2hvcC8...
        public String path;
        public String method;  // lowercase, e.g. "get"
    }

    private EndpointModels() {
    }
}
