package ai.apisec.relay.apisec.model;

import java.util.List;

/**
 * GET /v1/applications/{appId}/instances/{instanceId}/auths
 *
 * Auths are nested under instanceCredentials[], each with an authId and a
 * display name. Used to populate the scan auth picker. Partial by design.
 */
public final class AuthModels {

    public static final class AuthsResponse {
        public List<AuthItem> instanceCredentials;
    }

    public static final class AuthItem {
        public String authId;
        public String name;

        @Override
        public String toString() {
            String label = name == null || name.isBlank() ? "(unnamed auth)" : name;
            return label;
        }
    }

    private AuthModels() {
    }
}
