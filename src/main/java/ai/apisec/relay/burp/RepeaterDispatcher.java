package ai.apisec.relay.burp;

import ai.apisec.relay.apisec.model.DetectionModels.CapturedRequest;
import ai.apisec.relay.apisec.model.DetectionModels.ChainStep;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionDetail;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.repeater.Repeater;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Rebuilds the captured request from each test-chain step into a Montoya
 * HttpRequest and pushes it to Repeater. Multi-step findings (setup or auth
 * call, then the vulnerable call) arrive as separate tabs so the chain stays
 * intact.
 */
public class RepeaterDispatcher {

    private final Repeater repeater;
    private final Logging logging;

    public RepeaterDispatcher(Repeater repeater, Logging logging) {
        this.repeater = repeater;
        this.logging = logging;
    }

    /** Returns the number of Repeater tabs created. */
    public int sendChain(DetectionDetail detail) {
        return sendChain(detail, true);
    }

    /**
     * Rebuilds the chain into Repeater tabs.
     *
     * @param includeUnauthenticated when false, the unauthenticated control
     *     steps APIsec runs alongside each finding are skipped, so only the
     *     authenticated proof-of-concept request is sent. When true, both the
     *     authenticated request and the no-auth control are sent as before.
     * @return the number of Repeater tabs created.
     */
    public int sendChain(DetectionDetail detail, boolean includeUnauthenticated) {
        if (detail == null || detail.logs == null || detail.logs.testChain == null) {
            return 0;
        }
        List<Indexed> toSend = selectStepsToSend(detail, detail.logs.testChain, includeUnauthenticated, logging);
        int sent = 0;
        for (Indexed it : toSend) {
            HttpRequest req = build(it.step.request);
            if (req != null) {
                repeater.sendToRepeater(req, tabTitle(detail, it));
                sent++;
            } else {
                logging.logToError("Chain step " + it.index + " could not be rebuilt; skipped.");
            }
        }
        return sent;
    }

    /** A chain step paired with its original 1-based position, for tab labels. */
    static final class Indexed {
        final int index;
        final ChainStep step;

        Indexed(int index, ChainStep step) {
            this.index = index;
            this.step = step;
        }
    }

    /**
     * Decides which chain steps to replay.
     *
     * Rules:
     *  - Only steps that carry a replayable request (non-blank URL) are eligible.
     *  - Authenticated steps always send. The unauthenticated control sends only
     *    when includeUnauthenticated is true.
     *  - Floor: if that selection is empty but there IS replayable content (for
     *    example every step is unauthenticated and the box is off, or the
     *    authenticated step had no URL), the first replayable step is sent anyway
     *    so "Send to Repeater" never silently does nothing.
     *
     * Pure and side-effect free apart from logging, so it is unit-testable without
     * a Burp runtime.
     */
    static List<Indexed> selectStepsToSend(List<ChainStep> chain,
                                           boolean includeUnauthenticated,
                                           Logging logging) {
        return selectStepsToSend(null, chain, includeUnauthenticated, logging);
    }

    static List<Indexed> selectStepsToSend(DetectionDetail detail,
                                           List<ChainStep> chain,
                                           boolean includeUnauthenticated,
                                           Logging logging) {
        List<Indexed> replayable = new ArrayList<>();
        int idx = 0;
        for (ChainStep step : chain) {
            idx++;
            if (step == null || step.request == null) {
                continue;
            }
            if (step.request.url == null || step.request.url.isBlank()) {
                if (logging != null) {
                    logging.logToError("Chain step " + idx + " has no request URL; not replayable.");
                }
                continue;
            }
            replayable.add(new Indexed(idx, step));
        }
        if (replayable.isEmpty()) {
            return replayable;
        }

        List<Indexed> selected = new ArrayList<>();
        Indexed primaryAuth = null;
        Indexed matchingAuth = null;
        Indexed primaryNoAuth = null;
        Indexed matchingNoAuth = null;
        for (Indexed it : replayable) {
            boolean unauthenticated = "no-auth".equals(authTag(it.step));
            if (unauthenticated) {
                if (primaryNoAuth == null) {
                    primaryNoAuth = it;
                }
                if (matchesFindingResource(detail, it.step)) {
                    matchingNoAuth = it;
                }
            } else {
                primaryAuth = it;
                if (matchesFindingResource(detail, it.step)) {
                    matchingAuth = it;
                }
            }
        }
        if (matchingAuth != null) {
            primaryAuth = matchingAuth;
        }
        if (matchingNoAuth != null) {
            primaryNoAuth = matchingNoAuth;
        }
        if (primaryAuth != null) {
            selected.add(primaryAuth);
        }
        if (includeUnauthenticated && primaryNoAuth != null) {
            selected.add(primaryNoAuth);
        }
        if (selected.isEmpty()) {
            // Never do nothing when there is replayable content: send the primary.
            selected.add(replayable.get(0));
        }
        return selected;
    }

    private static boolean matchesFindingResource(DetectionDetail detail, ChainStep step) {
        if (detail == null || detail.resource == null || detail.resource.isBlank()
                || step == null || step.request == null || step.request.url == null) {
            return false;
        }
        String expected = stripQuery(detail.resource.trim());
        String actual = pathFromUrl(step.request.url.trim());
        return !expected.isBlank() && expected.equals(actual);
    }

    private static String pathFromUrl(String url) {
        try {
            String path = URI.create(url).getPath();
            return path == null ? "" : path;
        } catch (Exception ignored) {
            return stripQuery(url);
        }
    }

    private static String stripQuery(String value) {
        int q = value.indexOf('?');
        return q >= 0 ? value.substring(0, q) : value;
    }

    private HttpRequest build(CapturedRequest cr) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(cr.url);
            if (cr.method != null && !cr.method.isBlank()) {
                req = req.withMethod(cr.method.toUpperCase());
            }
            if (cr.headers != null) {
                for (Map.Entry<String, String> h : cr.headers.entrySet()) {
                    String name = h.getKey();
                    if (name == null || name.isBlank()) {
                        continue;
                    }
                    // Host comes from the URL, Content-Length is recomputed by Burp.
                    if (name.equalsIgnoreCase("host") || name.equalsIgnoreCase("content-length")) {
                        continue;
                    }
                    // One malformed header must not sink the whole request: a real
                    // captured Authorization/JWT header is exactly the value we most
                    // need to preserve, so tolerate a per-header failure and continue.
                    try {
                        req = req.withAddedHeader(name, h.getValue() == null ? "" : h.getValue());
                    } catch (Exception headerEx) {
                        logging.logToError("Skipped header \"" + name + "\" while rebuilding "
                                + cr.url + " :: " + headerEx.getMessage());
                    }
                }
            }
            String replayBody = bodyForReplay(cr.body);
            if (replayBody != null) {
                req = req.withBody(replayBody);
            }
            return req;
        } catch (Exception e) {
            logging.logToError("Could not build request for " + cr.url + " :: " + e.getMessage());
            return null;
        }
    }

    static String bodyForReplay(String body) {
        if (body == null) {
            return null;
        }
        String trimmed = body.trim();
        if (trimmed.isEmpty() || trimmed.equalsIgnoreCase("null")) {
            return null;
        }
        return body;
    }

    /**
     * Labels the auth posture of a chain step so identical-looking tabs are
     * distinguishable. APIsec probes each finding with an authenticated call and
     * an unauthenticated control, so the two Repeater tabs share a method and URL
     * but differ here. Prefers APIsec's own authName; falls back to inspecting the
     * replayed Authorization header.
     */
    static String authTag(ChainStep step) {
        if (step != null && step.authName != null && !step.authName.isBlank()) {
            return "auth:" + step.authName.trim();
        }
        if (step != null && step.request != null && step.request.headers != null) {
            for (Map.Entry<String, String> h : step.request.headers.entrySet()) {
                if (h.getKey() != null && h.getKey().equalsIgnoreCase("authorization")
                        && h.getValue() != null && !h.getValue().isBlank()) {
                    return "auth";
                }
            }
        }
        return "no-auth";
    }

    static String tabTitle(DetectionDetail detail, Indexed it) {
        String method = it == null || it.step == null || it.step.request == null || it.step.request.method == null
                ? "" : it.step.request.method.toUpperCase();
        String resource = detail == null || detail.resource == null ? "" : detail.resource;
        return method + " " + resource + " [" + authTag(it == null ? null : it.step) + "]";
    }
}
