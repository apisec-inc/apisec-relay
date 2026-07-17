package ai.apisec.relay.ui;

import ai.apisec.relay.apisec.model.ApplicationModels.AppItem;
import ai.apisec.relay.apisec.model.ApplicationModels.InstanceItem;
import ai.apisec.relay.apisec.model.AuthModels.AuthItem;

/**
 * Pre-submit guard for the Test set write path.
 *
 * Blocks before any APIsec mutation when the selected target is incomplete, the
 * active set has no staged requests, or the operator has not deliberately chosen
 * a scan auth. The "No auth" sentinel is a valid explicit auth choice and is
 * normalized to a null scanWithAuthId so Gson omits it from the scan payload.
 */
final class TestSetSubmissionValidator {

    private TestSetSubmissionValidator() {
    }

    static Result validate(AppItem app, InstanceItem inst, int activeSetSize,
                           int selectedAuthIndex, AuthItem selectedAuth) {
        if (app == null || inst == null) {
            return Result.blocked("Pick an application and instance in the header first.");
        }
        if (activeSetSize <= 0) {
            return Result.blocked("Nothing staged to submit. Stage requests from Burp first.");
        }
        if (selectedAuthIndex < 0) {
            return Result.blocked("Select a scan auth first, including 'No auth' for an unauthenticated scan.");
        }
        if (selectedAuth == null || selectedAuth.authId == null || selectedAuth.authId.isBlank()) {
            return Result.allowed(null, "No auth (unauthenticated scan)");
        }
        return Result.allowed(selectedAuth.authId.trim(), String.valueOf(selectedAuth));
    }

    static final class Result {
        private final boolean allowed;
        private final String message;
        private final String authId;
        private final String authLabel;

        private Result(boolean allowed, String message, String authId, String authLabel) {
            this.allowed = allowed;
            this.message = message;
            this.authId = authId;
            this.authLabel = authLabel;
        }

        static Result blocked(String message) {
            return new Result(false, message, null, null);
        }

        static Result allowed(String authId, String authLabel) {
            return new Result(true, null, authId, authLabel);
        }

        boolean allowed() {
            return allowed;
        }

        String message() {
            return message;
        }

        String authId() {
            return authId;
        }

        String authLabel() {
            return authLabel;
        }
    }
}
