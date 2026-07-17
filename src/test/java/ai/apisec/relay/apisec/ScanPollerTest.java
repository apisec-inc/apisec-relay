package ai.apisec.relay.apisec;

import ai.apisec.relay.apisec.model.ScanModels.ScanStatus;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

final class ScanPollerTest {

    @Test
    void pollsUntilStatusIsComplete() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        AtomicInteger sleeps = new AtomicInteger();
        ScanPoller poller = new ScanPoller(5, sleeps::incrementAndGet);

        ScanStatus result = poller.pollUntilComplete(() -> status(
                calls.incrementAndGet() < 3 ? "Running" : "Complete"));

        assertEquals("Complete", result.status);
        assertEquals(3, calls.get());
        assertEquals(2, sleeps.get());
    }

    @Test
    void returnsLastStatusAfterMaxAttempts() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        AtomicInteger sleeps = new AtomicInteger();
        ScanPoller poller = new ScanPoller(2, sleeps::incrementAndGet);
        ScanStatus running = status("Running");

        ScanStatus result = poller.pollUntilComplete(() -> {
            calls.incrementAndGet();
            return running;
        });

        assertSame(running, result);
        assertEquals(2, calls.get());
        assertEquals(1, sleeps.get());
    }

    private static ScanStatus status(String value) {
        ScanStatus status = new ScanStatus();
        status.scanId = "scan-123";
        status.status = value;
        return status;
    }
}
