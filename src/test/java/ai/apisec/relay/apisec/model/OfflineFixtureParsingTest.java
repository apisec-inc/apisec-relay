package ai.apisec.relay.apisec.model;

import ai.apisec.relay.apisec.model.ApplicationModels.AppDetail;
import ai.apisec.relay.apisec.model.ApplicationModels.AppsResponse;
import ai.apisec.relay.apisec.model.DetectionModels.ChainStep;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionDetail;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionsResponse;
import ai.apisec.relay.apisec.model.DetectionModels.VulnItem;
import com.google.gson.Gson;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class OfflineFixtureParsingTest {
    private static final Gson GSON = new Gson();

    @Test
    void detectionDetailFixtureDeserializesReplayRequestChain() throws IOException {
        DetectionDetail detail = fixture("/fixtures/detection_detail.json", DetectionDetail.class);

        assertNotNull(detail.detectionId);
        assertNotNull(detail.logs);
        assertNotNull(detail.logs.testChain);
        assertFalse(detail.logs.testChain.isEmpty());

        ChainStep firstStep = detail.logs.testChain.get(0);
        assertNotNull(firstStep.request);
        assertNotNull(firstStep.request.method);
        assertFalse(firstStep.request.method.isBlank());
        assertNotNull(firstStep.request.url);
        assertFalse(firstStep.request.url.isBlank());
        assertNotNull(firstStep.request.headers);
        assertFalse(firstStep.request.headers.isEmpty());
    }

    @Test
    void detectionsListFixtureFlattensToRowsWithDetectionIds() throws IOException {
        DetectionsResponse response = fixture("/fixtures/detections_list.json", DetectionsResponse.class);

        assertNotNull(response.detections);
        List<VulnItem> rows = response.detections.stream()
                .filter(Objects::nonNull)
                .filter(block -> block.data != null && block.data.vulnerabilities != null)
                .flatMap(block -> block.data.vulnerabilities.stream())
                .filter(Objects::nonNull)
                .toList();

        assertFalse(rows.isEmpty());
        assertTrue(rows.stream().anyMatch(row -> row.detectionId != null && !row.detectionId.isBlank()));
    }

    @Test
    void detectionsListExposesSeverityAndOwaspOnVulnerabilities() throws IOException {
        DetectionsResponse response = fixture("/fixtures/detections_list.json", DetectionsResponse.class);

        VulnItem withResult = response.detections.stream()
                .filter(Objects::nonNull)
                .filter(b -> b.data != null && b.data.vulnerabilities != null)
                .flatMap(b -> b.data.vulnerabilities.stream())
                .filter(Objects::nonNull)
                .filter(v -> v.testResult != null)
                .findFirst()
                .orElse(null);

        assertNotNull(withResult, "expected at least one vulnerability with a testResult");
        assertNotNull(withResult.testResult.cvssQualifier);
        assertNotNull(withResult.testResult.cvssScore);
        assertNotNull(withResult.testResult.owaspTags);
        assertFalse(withResult.testResult.owaspTags.isEmpty());
    }

    @Test
    void detectionsListAcceptsDecimalCvssScores() {
        String json = "{\"detections\":[{\"data\":{\"vulnerabilities\":[{"
                + "\"detectionId\":\"det-1\","
                + "\"testResult\":{\"cvssScore\":7.5,\"cvssQualifier\":\"High\",\"owaspTags\":[\"API1\"]}"
                + "}]}}]}";

        DetectionsResponse response = GSON.fromJson(json, DetectionsResponse.class);
        VulnItem row = response.detections.get(0).data.vulnerabilities.get(0);

        assertEquals(Double.valueOf(7.5), row.testResult.cvssScore);
    }

    @Test
    void applicationsListFixtureDeserializesShape() throws IOException {
        AppsResponse response = fixture("/fixtures/applications_list.json", AppsResponse.class);

        assertNotNull(response.applications);
        assertFalse(response.applications.isEmpty());
        assertTrue(response.applications.stream()
                .anyMatch(app -> app != null
                        && app.applicationId != null
                        && app.applicationName != null
                        && app.applicationType != null));
    }

    @Test
    void applicationDetailFixtureDeserializesShape() throws IOException {
        AppDetail detail = fixture("/fixtures/application_detail.json", AppDetail.class);

        assertNotNull(detail.applicationId);
        assertNotNull(detail.applicationName);
        assertNotNull(detail.instances);
        assertFalse(detail.instances.isEmpty());
        assertTrue(detail.instances.stream()
                .anyMatch(instance -> instance != null
                        && instance.instanceId != null
                        && instance.hostUrl != null));
    }

    private static <T> T fixture(String resourcePath, Class<T> type) throws IOException {
        try (InputStream stream = OfflineFixtureParsingTest.class.getResourceAsStream(resourcePath)) {
            assertNotNull(stream, "Missing fixture resource: " + resourcePath);
            try (Reader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                return GSON.fromJson(reader, type);
            }
        }
    }
}
