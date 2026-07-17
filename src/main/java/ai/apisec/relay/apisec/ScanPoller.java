package ai.apisec.relay.apisec;

import ai.apisec.relay.apisec.model.ScanModels.ScanStatus;

import java.io.IOException;

/** Polls GET scans/{scanId} until APIsec reports Complete or attempts are exhausted. */
public final class ScanPoller {
    private static final int DEFAULT_MAX_ATTEMPTS = 60;
    private static final Sleeper DEFAULT_SLEEPER = () -> Thread.sleep(5_000L);

    private final int maxAttempts;
    private final Sleeper sleeper;

    public ScanPoller() {
        this(DEFAULT_MAX_ATTEMPTS, DEFAULT_SLEEPER);
    }

    ScanPoller(int maxAttempts, Sleeper sleeper) {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be at least 1");
        }
        this.maxAttempts = maxAttempts;
        this.sleeper = sleeper == null ? DEFAULT_SLEEPER : sleeper;
    }

    public ScanStatus pollUntilComplete(ScanStatusSupplier supplier)
            throws IOException, InterruptedException {
        ScanStatus last = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            last = supplier.get();
            if (last != null && last.isComplete()) {
                return last;
            }
            if (attempt < maxAttempts) {
                sleeper.sleep();
            }
        }
        return last;
    }

    @FunctionalInterface
    public interface ScanStatusSupplier {
        ScanStatus get() throws IOException, InterruptedException;
    }

    @FunctionalInterface
    interface Sleeper {
        void sleep() throws InterruptedException;
    }
}
