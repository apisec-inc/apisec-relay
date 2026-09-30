package ai.apisec.relay.ui;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TestSetSubmitResultTest {

    @Test
    void missingScanIdIsDetectable() {
        // A placeholder used to be substituted here, which made the
        // "APIsec did not return a scanId" branch unreachable.
        assertFalse(TestSetPanel.SubmitResult.submitted(null, null).hasScanId());
        assertFalse(TestSetPanel.SubmitResult.submitted("  ", null).hasScanId());
        assertTrue(TestSetPanel.SubmitResult.submitted("scan-1", null).hasScanId());
    }

    @Test
    void pollFailureKeepsTheScanId() {
        IOException err = new IOException("APIsec request returned no HTTP response");
        TestSetPanel.SubmitResult r = TestSetPanel.SubmitResult.pollFailed("scan-1", err);
        assertFalse(r.cancelled);
        assertEquals("scan-1", r.scanId);
        assertSame(err, r.pollError);
        assertNull(r.finalStatus);
    }
}
