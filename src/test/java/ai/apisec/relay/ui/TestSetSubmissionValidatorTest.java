package ai.apisec.relay.ui;

import ai.apisec.relay.apisec.model.ApplicationModels.AppItem;
import ai.apisec.relay.apisec.model.ApplicationModels.InstanceItem;
import ai.apisec.relay.apisec.model.AuthModels.AuthItem;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TestSetSubmissionValidatorTest {

    @Test
    void blocksSubmitWhenApplicationIsMissing() {
        TestSetSubmissionValidator.Result result = TestSetSubmissionValidator.validate(
                null, instance("inst-1"), 1, 0, noAuth());

        assertFalse(result.allowed());
        assertEquals("Pick an application and instance in the header first.", result.message());
    }

    @Test
    void blocksSubmitWhenInstanceIsMissing() {
        TestSetSubmissionValidator.Result result = TestSetSubmissionValidator.validate(
                app("app-1"), null, 1, 0, noAuth());

        assertFalse(result.allowed());
        assertEquals("Pick an application and instance in the header first.", result.message());
    }

    @Test
    void blocksSubmitWhenActiveSetIsEmptyBeforeAuthValidation() {
        TestSetSubmissionValidator.Result result = TestSetSubmissionValidator.validate(
                app("app-1"), instance("inst-1"), 0, -1, null);

        assertFalse(result.allowed());
        assertEquals("Nothing staged to submit. Stage requests from Burp first.", result.message());
    }

    @Test
    void requiresExplicitAuthChoiceWhenActiveSetHasRequests() {
        TestSetSubmissionValidator.Result result = TestSetSubmissionValidator.validate(
                app("app-1"), instance("inst-1"), 2, -1, null);

        assertFalse(result.allowed());
        assertEquals("Select a scan auth first, including 'No auth' for an unauthenticated scan.", result.message());
    }

    @Test
    void allowsExplicitNoAuthChoiceAndNormalizesAuthIdToNull() {
        TestSetSubmissionValidator.Result result = TestSetSubmissionValidator.validate(
                app("app-1"), instance("inst-1"), 2, 0, noAuth());

        assertTrue(result.allowed());
        assertNull(result.authId());
        assertEquals("No auth (unauthenticated scan)", result.authLabel());
    }

    @Test
    void allowsExplicitCredentialChoiceAndTrimsAuthId() {
        AuthItem credential = auth("  auth-123  ", "Operator token");

        TestSetSubmissionValidator.Result result = TestSetSubmissionValidator.validate(
                app("app-1"), instance("inst-1"), 2, 1, credential);

        assertTrue(result.allowed());
        assertEquals("auth-123", result.authId());
        assertEquals("Operator token", result.authLabel());
    }

    private static AppItem app(String id) {
        AppItem app = new AppItem();
        app.applicationId = id;
        app.applicationName = "App";
        return app;
    }

    private static InstanceItem instance(String id) {
        InstanceItem instance = new InstanceItem();
        instance.instanceId = id;
        instance.hostUrl = "https://example.test";
        return instance;
    }

    private static AuthItem noAuth() {
        return auth(null, "No auth");
    }

    private static AuthItem auth(String id, String name) {
        AuthItem auth = new AuthItem();
        auth.authId = id;
        auth.name = name;
        return auth;
    }
}
