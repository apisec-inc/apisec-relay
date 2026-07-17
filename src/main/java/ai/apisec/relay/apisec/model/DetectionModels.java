package ai.apisec.relay.apisec.model;

import java.util.List;
import java.util.Map;

/**
 * Maps the detections list and the per-detection detail.
 *
 * The detail carries logs.testChain, and each step holds the exact request
 * APIsec issued, real Authorization header and all. That is the payload the
 * read path replays into Repeater.
 */
public final class DetectionModels {

    // GET .../detections?include=metadata&slim=true
    public static final class DetectionsResponse {
        public List<CategoryBlock> detections;
    }

    public static final class CategoryBlock {
        public NameId category;
        public NameId test;
        public DataBlock data;
    }

    public static final class NameId {
        public String id;
        public String name;
    }

    public static final class DataBlock {
        public List<VulnItem> vulnerabilities;
    }

    public static final class VulnItem {
        public String detectionId;
        public String endpointId;
        public String method;
        public String resource;
        public String status;
        public TestResult testResult;
    }

    // A2: severity + OWASP arrive on the list response under vulnerabilities[].testResult.
    public static final class TestResult {
        public Double cvssScore;
        public String cvssQualifier;
        public java.util.List<String> owaspTags;
    }

    // GET .../detections/{detectionId}
    public static final class DetectionDetail {
        public String detectionId;
        public String method;
        public String resource;
        public String status;
        public String cvssQualifier;
        public Double cvssScore;
        public Logs logs;
    }

    public static final class Logs {
        public List<ChainStep> testChain;
    }

    public static final class ChainStep {
        public String category;
        public String roleName;
        public String authName;
        public CapturedRequest request;
    }

    public static final class CapturedRequest {
        public String method;
        public String url;
        public Map<String, String> headers;
        public String body;
    }

    private DetectionModels() {
    }
}
