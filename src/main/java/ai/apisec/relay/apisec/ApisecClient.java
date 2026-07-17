package ai.apisec.relay.apisec;

import ai.apisec.relay.apisec.model.ApplicationModels.AppDetail;
import ai.apisec.relay.apisec.model.ApplicationModels.AppItem;
import ai.apisec.relay.apisec.model.ApplicationModels.AppsResponse;
import ai.apisec.relay.apisec.model.AuthModels.AuthItem;
import ai.apisec.relay.apisec.model.AuthModels.AuthsResponse;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionDetail;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionsResponse;
import ai.apisec.relay.apisec.model.EndpointModels.EndpointGroup;
import ai.apisec.relay.apisec.model.EndpointModels.EndpointItem;
import ai.apisec.relay.apisec.model.EndpointModels.EndpointsResponse;
import ai.apisec.relay.apisec.model.ScanModels.NewEndpoint;
import ai.apisec.relay.apisec.model.ScanModels.ScanInitResponse;
import ai.apisec.relay.apisec.model.ScanModels.ScanRequest;
import ai.apisec.relay.apisec.model.ScanModels.ScanStatus;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Talks to the APIsec control plane through Burp's Montoya HTTP API so upstream
 * proxy settings, TLS settings, and corporate network routing are honored.
 */
public class ApisecClient {

    private static final int ERROR_TEXT_LIMIT = 160;
    private static final Pattern JSON_ERROR_FIELD = Pattern.compile(
            "\\\"(?:message|error|title|detail)\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"])*)\\\"",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern BEARER_TOKEN = Pattern.compile(
            "(?i)bearer\\s+[A-Za-z0-9._~+/=-]{8,}");
    private static final Pattern AUTHORIZATION_HEADER = Pattern.compile(
            "(?i)(authorization\\s*[:=]\\s*)[^,;\\s}]+(?:\\s+[^,;\\s}]+)?");
    private static final Pattern PAT_LIKE_VALUE = Pattern.compile(
            "(?i)(pat|token|secret|api[_-]?key)(\\s*[:=]\\s*|\\\"\\s*:\\s*\\\")[^,;\\s}\"]+");

    private final Logging logging;
    private final Http burpHttp;
    private final Gson gson = new Gson();

    private String host = "https://api.apisecapps.com";
    private String pat = "";

    public ApisecClient(Logging logging) {
        this(logging, null);
    }

    public ApisecClient(Logging logging, Http burpHttp) {
        this.logging = logging;
        this.burpHttp = burpHttp;
    }

    public void configure(String host, String pat) {
        if (host != null && !host.isBlank()) {
            this.host = host.trim().replaceAll("/+$", "");
        }
        this.pat = pat == null ? "" : pat.trim();
    }

    /**
     * Capability that authorizes a single mutating submit. The write methods
     * refuse a null token, so a POST can only reach APIsec when the caller has
     * minted one via {@link #authorizeWrite()} — which the Test set panel does
     * only after the operator confirms. Carrying the intent as a per-call
     * argument keeps it off shared, cross-thread client state.
     */
    public static final class WriteAuthorization {
        private WriteAuthorization() {
        }
    }

    /**
     * Mints a write capability. Call only after explicit user confirmation of a
     * mutating submit. A write-scoped PAT is still required server-side; a
     * read-only PAT is rejected by APIsec with a 4xx.
     */
    public WriteAuthorization authorizeWrite() {
        return new WriteAuthorization();
    }

    public List<AppItem> listApplications() throws IOException, InterruptedException {
        List<AppItem> all = new ArrayList<>();
        String token = "";
        do {
            String url = host + "/v1/applications?nextToken=" + enc(token);
            AppsResponse page = gson.fromJson(get(url), AppsResponse.class);
            if (page == null) break;
            if (page.applications != null) all.addAll(page.applications);
            token = page.nextToken;
        } while (token != null && !token.isBlank());
        return all;
    }

    public AppDetail getApplication(String applicationId)
            throws IOException, InterruptedException {
        String url = host + "/v1/applications/" + enc(applicationId);
        return gson.fromJson(get(url), AppDetail.class);
    }

    public DetectionsResponse listDetections(String applicationId, String instanceId)
            throws IOException, InterruptedException {
        String url = host + "/v1/applications/" + enc(applicationId)
                + "/instances/" + enc(instanceId)
                + "/detections?include=metadata&slim=true&excludeDetectionsWithStatus=DISMISSED";
        return gson.fromJson(get(url), DetectionsResponse.class);
    }

    public DetectionDetail getDetection(String applicationId, String instanceId, String detectionId)
            throws IOException, InterruptedException {
        String url = host + "/v1/applications/" + enc(applicationId)
                + "/instances/" + enc(instanceId)
                + "/detections/" + enc(detectionId);
        return gson.fromJson(get(url), DetectionDetail.class);
    }

    /**
     * Lists the endpoints already present on an instance. Used to dedup a staged
     * test set: an endpoint whose computed endpointId is already here is PRESENT,
     * otherwise NEW.
     */
    public List<EndpointItem> listEndpoints(String applicationId, String instanceId)
            throws IOException, InterruptedException {
        String url = host + "/v1/applications/" + enc(applicationId)
                + "/instances/" + enc(instanceId)
                + "/endpoints?include=metadata&slim=true";
        EndpointsResponse resp = gson.fromJson(get(url), EndpointsResponse.class);
        List<EndpointItem> flat = new ArrayList<>();
        if (resp != null && resp.endpointGroups != null) {
            for (EndpointGroup g : resp.endpointGroups) {
                if (g != null && g.endpoints != null) {
                    for (EndpointItem e : g.endpoints) {
                        if (e != null) {
                            flat.add(e);
                        }
                    }
                }
            }
        }
        return flat;
    }

    /** Lists the auths configured on an instance, to populate the scan auth picker. */
    public List<AuthItem> listAuths(String applicationId, String instanceId)
            throws IOException, InterruptedException {
        String url = host + "/v1/applications/" + enc(applicationId)
                + "/instances/" + enc(instanceId) + "/auths";
        AuthsResponse resp = gson.fromJson(get(url), AuthsResponse.class);
        List<AuthItem> auths = new ArrayList<>();
        if (resp != null && resp.instanceCredentials != null) {
            for (AuthItem a : resp.instanceCredentials) {
                if (a != null && a.authId != null && !a.authId.isBlank()) {
                    auths.add(a);
                }
            }
        }
        return auths;
    }

    /**
     * Adds endpoints to an instance. Send only endpoints not already present.
     * NewEndpoint.method must be LOWERCASE; endpoint is the path; payload is the
     * request body string ("" if none). No-op if the list is empty.
     */
    public void addEndpoints(String applicationId, String instanceId, List<NewEndpoint> endpoints,
                             WriteAuthorization auth)
            throws IOException, InterruptedException {
        if (endpoints == null || endpoints.isEmpty()) {
            return;
        }
        String url = host + "/v1/applications/" + enc(applicationId)
                + "/instances/" + enc(instanceId) + "/add-endpoints";
        post(url, gson.toJson(endpoints), auth);
    }

    /**
     * Starts a scan over the given base64 endpointIds.
     *
     * @param authId the APIsec auth to scan with, or null/blank for an
     *     unauthenticated scan. When null, scanWithAuthId is omitted from the body
     *     (Gson skips null fields), which APIsec treats as a no-auth scan.
     * @return the scanId.
     */
    public String initiateScan(String applicationId, String instanceId,
                               List<String> endpointIds, String authId, WriteAuthorization auth)
            throws IOException, InterruptedException {
        if (endpointIds == null || endpointIds.isEmpty()) {
            throw new IOException("Cannot scan: no endpoints in the staged set.");
        }
        String url = host + "/v1/applications/" + enc(applicationId)
                + "/instances/" + enc(instanceId) + "/scan";
        String scanAuth = (authId == null || authId.isBlank()) ? null : authId.trim();
        ScanRequest payload = new ScanRequest(endpointIds, scanAuth);
        ScanInitResponse resp = gson.fromJson(post(url, gson.toJson(payload), auth), ScanInitResponse.class);
        return resp == null ? null : resp.scanId;
    }

    /** Polls a scan's progress. status reaches "Complete". */
    public ScanStatus getScan(String applicationId, String instanceId, String scanId)
            throws IOException, InterruptedException {
        String url = host + "/v1/applications/" + enc(applicationId)
                + "/instances/" + enc(instanceId) + "/scans/" + enc(scanId);
        return gson.fromJson(get(url), ScanStatus.class);
    }

    private String get(String url) throws IOException, InterruptedException {
        if (pat.isBlank()) {
            throw new IOException("No PAT configured. Set host and PAT, then save.");
        }
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("GET")
                .withAddedHeader("Authorization", "Bearer " + pat)
                .withAddedHeader("Accept", "application/json");
        HttpRequestResponse resp = send(req);
        int code = resp.response().statusCode();
        String body = resp.response().bodyToString();
        if (code < 200 || code >= 300) {
            URI uri = URI.create(url);
            String endpoint = endpointCategory(uri);
            String safeText = sanitizedErrorText(body);
            logError("APIsec control-plane error: method=GET endpoint="
                    + endpoint + " status=" + code + " error=\"" + safeText + "\"");
            if (verboseResponseLoggingEnabled()) {
                logError("APIsec debug response logging enabled. Sanitized response: "
                        + sanitizedVerboseResponse(body));
            }
            throw new IOException("APIsec returned HTTP " + code);
        }
        return body;
    }

    private String post(String url, String jsonBody, WriteAuthorization auth)
            throws IOException, InterruptedException {
        if (auth == null) {
            throw new IOException("Write path is unauthorized. Confirm Test set submit before mutating APIsec.");
        }
        if (pat.isBlank()) {
            throw new IOException("No PAT configured. Set host and PAT, then save.");
        }
        HttpRequest req = HttpRequest.httpRequestFromUrl(url)
                .withMethod("POST")
                .withAddedHeader("Authorization", "Bearer " + pat)
                .withAddedHeader("Accept", "application/json")
                .withAddedHeader("Content-Type", "application/json")
                .withBody(jsonBody == null ? "" : jsonBody);
        HttpRequestResponse resp = send(req);
        int code = resp.response().statusCode();
        String body = resp.response().bodyToString();
        if (code < 200 || code >= 300) {
            URI uri = URI.create(url);
            String endpoint = endpointCategory(uri);
            String safeText = sanitizedErrorText(body);
            logError("APIsec control-plane error: method=POST endpoint="
                    + endpoint + " status=" + code + " error=\"" + safeText + "\"");
            if (verboseResponseLoggingEnabled()) {
                logError("APIsec debug response logging enabled. Sanitized response: "
                        + sanitizedVerboseResponse(body));
            }
            throw new IOException("APIsec returned HTTP " + code);
        }
        return body;
    }

    private HttpRequestResponse send(HttpRequest request) throws IOException {
        if (burpHttp == null) {
            throw new IOException("Burp HTTP API is unavailable. Reload APIsec Relay in Burp.");
        }
        HttpRequestResponse response = burpHttp.sendRequest(request);
        if (response == null || !response.hasResponse()) {
            throw new IOException("APIsec request returned no HTTP response");
        }
        return response;
    }

    private void logError(String message) {
        if (logging != null) {
            logging.logToError(message);
        }
    }

    static String endpointCategory(URI uri) {
        String path = uri == null ? "" : uri.getPath();
        if (path == null || path.isBlank()) {
            return "unknown";
        }
        String[] parts = path.replaceAll("^/+", "").split("/+");
        if (parts.length == 2 && "v1".equals(parts[0]) && "applications".equals(parts[1])) {
            return "/v1/applications";
        }
        if (parts.length == 3 && "v1".equals(parts[0]) && "applications".equals(parts[1])) {
            return "/v1/applications/{applicationId}";
        }
        if (parts.length == 6
                && "v1".equals(parts[0])
                && "applications".equals(parts[1])
                && "instances".equals(parts[3])
                && "detections".equals(parts[5])) {
            return "/v1/applications/{applicationId}/instances/{instanceId}/detections";
        }
        if (parts.length == 7
                && "v1".equals(parts[0])
                && "applications".equals(parts[1])
                && "instances".equals(parts[3])
                && "detections".equals(parts[5])) {
            return "/v1/applications/{applicationId}/instances/{instanceId}/detections/{detectionId}";
        }
        if (parts.length == 7
                && "v1".equals(parts[0])
                && "applications".equals(parts[1])
                && "instances".equals(parts[3])
                && "scans".equals(parts[5])) {
            return "/v1/applications/{applicationId}/instances/{instanceId}/scans/{scanId}";
        }
        return path.replaceAll("/[0-9a-fA-F-]{8,}(?=/|$)", "/{id}");
    }

    static String sanitizedErrorText(String body) {
        String extracted = extractErrorText(body);
        String normalized = sanitizeSecrets(extracted)
                .replaceAll("[\\r\\n\\t]+", " ")
                .replaceAll("\\s{2,}", " ")
                .trim();
        if (normalized.isBlank()) {
            return "HTTP error response contained no safe error text";
        }
        if (normalized.length() > ERROR_TEXT_LIMIT) {
            return normalized.substring(0, ERROR_TEXT_LIMIT) + "...";
        }
        return normalized;
    }

    static String sanitizedVerboseResponse(String body) {
        String safe = sanitizeSecrets(body == null ? "" : body)
                .replaceAll("[\\r\\n\\t]+", " ")
                .replaceAll("\\s{2,}", " ")
                .trim();
        if (safe.isBlank()) {
            return "<empty>";
        }
        return safe.length() > 1000 ? safe.substring(0, 1000) + "..." : safe;
    }

    static boolean verboseResponseLoggingEnabled() {
        String property = System.getProperty("apisec.relay.debugResponses", "");
        String env = System.getenv("APISEC_RELAY_DEBUG_RESPONSES");
        return "true".equalsIgnoreCase(property.trim()) || "true".equalsIgnoreCase(env == null ? "" : env.trim());
    }

    private static String extractErrorText(String body) {
        if (body == null || body.isBlank()) {
            return "";
        }
        Matcher matcher = JSON_ERROR_FIELD.matcher(body);
        if (matcher.find()) {
            return matcher.group(1)
                    .replace("\\\"", "\"")
                    .replace("\\n", " ")
                    .replace("\\r", " ")
                    .replace("\\t", " ");
        }
        String trimmed = body.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            return "JSON error response without safe message field";
        }
        return trimmed;
    }

    private static String sanitizeSecrets(String text) {
        String safe = text == null ? "" : text;
        safe = AUTHORIZATION_HEADER.matcher(safe).replaceAll("$1[redacted]");
        safe = BEARER_TOKEN.matcher(safe).replaceAll("Bearer [redacted]");
        safe = PAT_LIKE_VALUE.matcher(safe).replaceAll("$1$2[redacted]");
        return safe;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }
}
