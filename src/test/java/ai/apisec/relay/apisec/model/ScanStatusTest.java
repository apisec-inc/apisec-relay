package ai.apisec.relay.apisec.model;

import ai.apisec.relay.apisec.model.ScanModels.ScanStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ScanStatusTest {

    @Test
    void completeStatusIsTerminalRegardlessOfCaseOrWhitespace() {
        ScanStatus status = new ScanStatus();
        status.status = "  complete  ";

        assertTrue(status.isComplete());
    }

    @Test
    void runningStatusIsNotTerminal() {
        ScanStatus status = new ScanStatus();
        status.status = "Running";

        assertFalse(status.isComplete());
    }
}
