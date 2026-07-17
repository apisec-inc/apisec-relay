package ai.apisec.relay.burp;

import ai.apisec.relay.apisec.model.DetectionModels.CapturedRequest;
import ai.apisec.relay.apisec.model.DetectionModels.ChainStep;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionDetail;
import ai.apisec.relay.apisec.model.DetectionModels.Logs;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class RepeaterDispatcherTest {
    @Test
    void replayBodyTreatsNullBlankAndLiteralNullAsAbsent() {
        assertNull(RepeaterDispatcher.bodyForReplay(null));
        assertNull(RepeaterDispatcher.bodyForReplay(""));
        assertNull(RepeaterDispatcher.bodyForReplay("   \t\n"));
        assertNull(RepeaterDispatcher.bodyForReplay("null"));
        assertNull(RepeaterDispatcher.bodyForReplay("NULL"));
        assertNull(RepeaterDispatcher.bodyForReplay("  NuLl  "));
    }

    @Test
    void replayBodyPreservesIntentionalNonNullBodiesUnchanged() {
        assertEquals("{}", RepeaterDispatcher.bodyForReplay("{}"));
        assertEquals(" [] ", RepeaterDispatcher.bodyForReplay(" [] "));
        assertEquals("nullish", RepeaterDispatcher.bodyForReplay("nullish"));
        assertEquals("{\"value\":null}", RepeaterDispatcher.bodyForReplay("{\"value\":null}"));
    }

    @Test
    void authTagPrefersApisecAuthName() {
        ChainStep step = new ChainStep();
        step.authName = "UserA";
        assertEquals("auth:UserA", RepeaterDispatcher.authTag(step));
    }

    @Test
    void authTagFallsBackToAuthorizationHeaderWhenAuthNameMissing() {
        ChainStep step = new ChainStep();
        step.authName = null;
        step.request = new CapturedRequest();
        step.request.headers = new LinkedHashMap<>();
        step.request.headers.put("Authorization", "Bearer eyJhbG...jNuQ");
        assertEquals("auth", RepeaterDispatcher.authTag(step));
    }

    @Test
    void authTagReportsNoAuthForUnauthenticatedControlStep() {
        ChainStep step = new ChainStep();
        step.authName = null;
        step.request = new CapturedRequest();
        step.request.headers = new LinkedHashMap<>();
        step.request.headers.put("content-type", "application/json");
        assertEquals("no-auth", RepeaterDispatcher.authTag(step));
    }

    @Test
    void authTagHandlesNullStepAndBlankAuthName() {
        assertEquals("no-auth", RepeaterDispatcher.authTag(null));
        ChainStep blank = new ChainStep();
        blank.authName = "   ";
        assertEquals("no-auth", RepeaterDispatcher.authTag(blank));
    }

    @Test
    void standardApisecTwoStepChainClassifiesAsAuthThenNoAuthControl() {
        // Mirrors the real detection fixture: an authenticated probe followed by
        // an unauthenticated control. The unauth toggle keys on the "no-auth" tag.
        DetectionDetail detail = new DetectionDetail();
        detail.detectionId = "019b938e-1ba0-744c-a1e1-dd7396cd6c27";
        detail.resource = "/workshop/api/shop/orders/all";
        detail.logs = new Logs();
        detail.logs.testChain = new ArrayList<>();

        ChainStep authed = new ChainStep();
        authed.authName = "UserA";
        authed.request = new CapturedRequest();
        authed.request.method = "get";
        authed.request.url = "http://crapi2.example.com/workshop/api/shop/orders/all";
        authed.request.headers = new LinkedHashMap<>();
        authed.request.headers.put("Authorization", "Bearer eyJhbG...jNuQ");

        ChainStep control = new ChainStep();
        control.authName = null;
        control.request = new CapturedRequest();
        control.request.method = "get";
        control.request.url = "http://crapi2.example.com/workshop/api/shop/orders/all";
        control.request.headers = new LinkedHashMap<>();
        control.request.headers.put("content-type", "application/json");

        detail.logs.testChain.add(authed);
        detail.logs.testChain.add(control);

        List<String> tags = new ArrayList<>();
        for (ChainStep s : detail.logs.testChain) {
            tags.add(RepeaterDispatcher.authTag(s));
        }
        assertEquals(List.of("auth:UserA", "no-auth"), tags);

        // With the toggle OFF, exactly one step (the no-auth control) would be skipped.
        long skipped = tags.stream().filter("no-auth"::equals).count();
        assertEquals(1, skipped);
        long kept = tags.stream().filter(t -> !"no-auth".equals(t)).count();
        assertTrue(kept >= 1);
    }

    // ---- selectStepsToSend: the actual Send-to-Repeater selection ----

    private static ChainStep step(String authName, String authHeader, String url) {
        ChainStep s = new ChainStep();
        s.authName = authName;
        s.request = new CapturedRequest();
        s.request.method = "get";
        s.request.url = url;
        s.request.headers = new LinkedHashMap<>();
        if (authHeader != null) {
            s.request.headers.put("Authorization", authHeader);
        } else {
            s.request.headers.put("content-type", "application/json");
        }
        return s;
    }

    private static ChainStep authedStep() {
        return step("UserA", "Bearer eyJhbG...jNuQ", "http://crapi2.example.com/workshop/api/shop/orders/all");
    }

    private static ChainStep controlStep() {
        return step(null, null, "http://crapi2.example.com/workshop/api/shop/orders/all");
    }

    @Test
    void includeUnauthTrueSendsBothAuthAndControl() {
        List<ChainStep> chain = List.of(authedStep(), controlStep());
        List<RepeaterDispatcher.Indexed> sel =
                RepeaterDispatcher.selectStepsToSend(chain, true, null);
        assertEquals(2, sel.size());
        assertEquals("auth:UserA", RepeaterDispatcher.authTag(sel.get(0).step));
        assertEquals("no-auth", RepeaterDispatcher.authTag(sel.get(1).step));
    }

    @Test
    void includeUnauthTrueSendsOnlyPrimaryAuthAndPrimaryControlWhenSetupStepsExist() {
        ChainStep setup = step("Setup", "Bearer setup-token", "http://crapi2.example.com/workshop/api/session");
        ChainStep exploit = authedStep();
        ChainStep control = controlStep();

        List<RepeaterDispatcher.Indexed> sel =
                RepeaterDispatcher.selectStepsToSend(List.of(setup, exploit, control), true, null);

        assertEquals(2, sel.size());
        assertEquals(2, sel.get(0).index);
        assertEquals("auth:UserA", RepeaterDispatcher.authTag(sel.get(0).step));
        assertEquals(3, sel.get(1).index);
        assertEquals("no-auth", RepeaterDispatcher.authTag(sel.get(1).step));
    }

    @Test
    void includeUnauthTrueSelectsNoAuthControlMatchingFindingResourceInsteadOfJwksProbe() {
        DetectionDetail detail = new DetectionDetail();
        detail.resource = "/identity/api/v2/vehicle/resend_email";

        ChainStep jwks = step(null, null, "http://crapi3.example.com/.well-known/jwks.json");
        ChainStep exploit = step("crapi1", "Bearer eyJhbG...jNuQ",
                "http://crapi3.example.com/identity/api/v2/vehicle/resend_email");
        ChainStep control = step(null, null,
                "http://crapi3.example.com/identity/api/v2/vehicle/resend_email");

        List<RepeaterDispatcher.Indexed> sel =
                RepeaterDispatcher.selectStepsToSend(detail, List.of(jwks, exploit, control), true, null);

        assertEquals(2, sel.size());
        assertEquals(2, sel.get(0).index);
        assertEquals("auth:crapi1", RepeaterDispatcher.authTag(sel.get(0).step));
        assertEquals(3, sel.get(1).index);
        assertEquals("no-auth", RepeaterDispatcher.authTag(sel.get(1).step));
        assertEquals("http://crapi3.example.com/identity/api/v2/vehicle/resend_email",
                sel.get(1).step.request.url);
    }

    @Test
    void repeaterTabTitleUsesMethodResourceAndAuthTag() {
        DetectionDetail detail = new DetectionDetail();
        detail.detectionId = "019b938e-1ba0-744c-a1e1-dd7396cd6c27";
        detail.resource = "/workshop/api/shop/orders/all";
        RepeaterDispatcher.Indexed indexed = new RepeaterDispatcher.Indexed(2, authedStep());

        String title = RepeaterDispatcher.tabTitle(detail, indexed);

        assertEquals("GET /workshop/api/shop/orders/all [auth:UserA]", title);
    }

    @Test
    void includeUnauthFalseSendsOnlyTheAuthenticatedStep() {
        // The reported bug: unchecked must still send the authenticated request.
        List<ChainStep> chain = List.of(authedStep(), controlStep());
        List<RepeaterDispatcher.Indexed> sel =
                RepeaterDispatcher.selectStepsToSend(chain, false, null);
        assertEquals(1, sel.size());
        assertEquals("auth:UserA", RepeaterDispatcher.authTag(sel.get(0).step));
    }

    @Test
    void floorSendsPrimaryWhenOnlyControlExistsAndUnauthIsOff() {
        // A finding whose only replayable step is unauthenticated must still send
        // something when the box is off, rather than doing nothing.
        List<ChainStep> chain = List.of(controlStep());
        List<RepeaterDispatcher.Indexed> sel =
                RepeaterDispatcher.selectStepsToSend(chain, false, null);
        assertEquals(1, sel.size());
        assertEquals("no-auth", RepeaterDispatcher.authTag(sel.get(0).step));
    }

    @Test
    void stepsWithoutReplayableUrlAreSkippedAndIndexesArePreserved() {
        ChainStep noUrl = new ChainStep();
        noUrl.authName = "UserA";
        noUrl.request = new CapturedRequest();
        noUrl.request.url = "  ";
        List<ChainStep> chain = new ArrayList<>();
        chain.add(noUrl);          // index 1, not replayable
        chain.add(authedStep());   // index 2
        chain.add(controlStep());  // index 3
        List<RepeaterDispatcher.Indexed> sel =
                RepeaterDispatcher.selectStepsToSend(chain, true, null);
        assertEquals(2, sel.size());
        assertEquals(2, sel.get(0).index);
        assertEquals(3, sel.get(1).index);
    }

    @Test
    void emptyOrAllUnreplayableChainSelectsNothing() {
        assertTrue(RepeaterDispatcher.selectStepsToSend(new ArrayList<>(), true, null).isEmpty());
        ChainStep noUrl = new ChainStep();
        noUrl.request = new CapturedRequest();
        noUrl.request.url = null;
        assertTrue(RepeaterDispatcher.selectStepsToSend(List.of(noUrl), true, null).isEmpty());
    }
}
