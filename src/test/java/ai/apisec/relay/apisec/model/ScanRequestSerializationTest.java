package ai.apisec.relay.apisec.model;

import ai.apisec.relay.apisec.model.ScanModels.ScanRequest;
import com.google.gson.Gson;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the scan body contract for authenticated vs unauthenticated scans (R2).
 * Gson omits null fields by default, so a null scanWithAuthId disappears from the
 * JSON, which APIsec treats as a no-auth scan.
 */
final class ScanRequestSerializationTest {

    private static final Gson GSON = new Gson();

    @Test
    void authenticatedScanIncludesScanWithAuthId() {
        ScanRequest req = new ScanRequest(List.of("EID1", "EID2"), "auth-123");
        String json = GSON.toJson(req);
        assertTrue(json.contains("\"scanWithAuthId\":\"auth-123\""), json);
        assertTrue(json.contains("\"endpointIds\""), json);
    }

    @Test
    void unauthenticatedScanOmitsScanWithAuthId() {
        ScanRequest req = new ScanRequest(List.of("EID1"), null);
        String json = GSON.toJson(req);
        assertFalse(json.contains("scanWithAuthId"), json);
        assertTrue(json.contains("\"endpointIds\""), json);
    }
}
