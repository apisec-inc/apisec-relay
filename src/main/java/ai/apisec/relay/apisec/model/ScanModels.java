package ai.apisec.relay.apisec.model;

import java.util.List;

/**
 * Write path: stage Burp requests into an APIsec instance and scan them.
 *
 * Two POSTs occur in one submit and the method casing differs between them:
 *  - add-endpoints uses the LOWERCASE method.
 *  - scan uses the base64 endpointId derived from the UPPERCASE method.
 * See ai.apisec.relay.apisec.EndpointIds. Do not let the casing leak across.
 */
public final class ScanModels {

    // One element of the POST .../add-endpoints body array.
    public static final class NewEndpoint {
        public String method;    // LOWERCASE, e.g. "get"
        public String endpoint;  // path, e.g. "/api/v1/users"
        public String payload;   // request body string, "" if none

        public NewEndpoint(String method, String endpoint, String payload) {
            this.method = method;
            this.endpoint = endpoint;
            this.payload = payload == null ? "" : payload;
        }
    }

    // POST .../scan body.
    public static final class ScanRequest {
        public List<String> endpointIds;  // base64 endpointIds (UPPERCASE-derived)
        public String scanWithAuthId;

        public ScanRequest(List<String> endpointIds, String scanWithAuthId) {
            this.endpointIds = endpointIds;
            this.scanWithAuthId = scanWithAuthId;
        }
    }

    // POST .../scan response.
    public static final class ScanInitResponse {
        public String scanId;
    }

    // GET .../scans/{scanId} response. Partial by design.
    public static final class ScanStatus {
        public String scanId;
        public String status;        // reaches "Complete"
        public String statusReason;

        /** True once the scan has reached its terminal "Complete" state. */
        public boolean isComplete() {
            return status != null && "complete".equalsIgnoreCase(status.trim());
        }
    }

    private ScanModels() {
    }
}
