package ai.apisec.relay.apisec;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApisecClientLoggingTest {

    @Test
    void endpointCategoryCollapsesApplicationListUrl() {
        String category = ApisecClient.endpointCategory(
                URI.create("https://api.apisecapps.com/v1/applications?nextToken=abc"));

        assertEquals("/v1/applications", category);
    }

    @Test
    void endpointCategoryCollapsesDetectionListUrl() {
        String category = ApisecClient.endpointCategory(URI.create(
                "https://api.apisecapps.com/v1/applications/app-123/instances/inst-456/detections?include=metadata"));

        assertEquals("/v1/applications/{applicationId}/instances/{instanceId}/detections", category);
    }

    @Test
    void endpointCategoryCollapsesDetectionDetailUrl() {
        String category = ApisecClient.endpointCategory(URI.create(
                "https://api.apisecapps.com/v1/applications/app-123/instances/inst-456/detections/det-789"));

        assertEquals("/v1/applications/{applicationId}/instances/{instanceId}/detections/{detectionId}", category);
    }

    @Test
    void endpointCategoryCollapsesScanStatusUrl() {
        String category = ApisecClient.endpointCategory(URI.create(
                "https://api.apisecapps.com/v1/applications/app-123/instances/inst-456/scans/scan-789"));

        assertEquals("/v1/applications/{applicationId}/instances/{instanceId}/scans/{scanId}", category);
    }

    @Test
    void sanitizedErrorTextExtractsSafeJsonMessage() {
        String body = "{\"message\":\"Unauthorized for tenant blue\",\"debug\":\"raw response body not logged\"}";

        assertEquals("Unauthorized for tenant blue", ApisecClient.sanitizedErrorText(body));
    }

    @Test
    void sanitizedErrorTextRedactsAuthorizationAndTokenValues() {
        String body = "{\"message\":\"Authorization: Bearer SecretBearerValue123 token=abc123456789 secret:shh987654321\"}";

        String safe = ApisecClient.sanitizedErrorText(body);

        assertFalse(safe.contains("Bearer"));
        assertTrue(safe.contains("token=[redacted]"));
        assertTrue(safe.contains("secret:[redacted]"));
        assertFalse(safe.contains("SecretBearerValue123"));
        assertFalse(safe.contains("abc123456789"));
        assertFalse(safe.contains("shh987654321"));
    }

    @Test
    void jsonWithoutSafeMessageDoesNotLeakRawResponse() {
        String body = "{\"request\":{\"headers\":{\"Authorization\":\"Bearer live-secret-token\"}},\"body\":\"private payload\"}";

        assertEquals("JSON error response without safe message field", ApisecClient.sanitizedErrorText(body));
    }

    @Test
    void verboseResponseLoggingDefaultsOff() {
        String prior = System.getProperty("apisec.relay.debugResponses");
        try {
            System.clearProperty("apisec.relay.debugResponses");
            assertFalse(ApisecClient.verboseResponseLoggingEnabled());
        } finally {
            if (prior == null) {
                System.clearProperty("apisec.relay.debugResponses");
            } else {
                System.setProperty("apisec.relay.debugResponses", prior);
            }
        }
    }

    @Test
    void verboseResponseLoggingRequiresExplicitLocalFlag() {
        String prior = System.getProperty("apisec.relay.debugResponses");
        try {
            System.setProperty("apisec.relay.debugResponses", "true");
            assertTrue(ApisecClient.verboseResponseLoggingEnabled());
        } finally {
            if (prior == null) {
                System.clearProperty("apisec.relay.debugResponses");
            } else {
                System.setProperty("apisec.relay.debugResponses", prior);
            }
        }
    }
}
