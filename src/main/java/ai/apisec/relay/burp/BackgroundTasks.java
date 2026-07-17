package ai.apisec.relay.burp;

import javax.swing.SwingWorker;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks every in-flight SwingWorker so the extension can cancel them all when
 * Burp unloads it. Without this, a worker blocked in scan polling could keep a
 * thread alive (and keep issuing HTTP requests through a stale MontoyaApi) for
 * minutes after unload. cancel(true) interrupts the worker thread, which
 * unblocks ScanPoller's sleep and aborts the poll loop.
 */
public final class BackgroundTasks {

    private final Set<SwingWorker<?, ?>> active = ConcurrentHashMap.newKeySet();
    private volatile boolean shutdown = false;

    /**
     * Starts a worker and tracks it until it reaches DONE. After
     * {@link #cancelAll()} has run, new workers are refused so an unloaded
     * extension cannot spawn fresh threads.
     */
    public void execute(SwingWorker<?, ?> worker) {
        if (worker == null || shutdown) {
            return;
        }
        active.add(worker);
        worker.addPropertyChangeListener(evt -> {
            if ("state".equals(evt.getPropertyName())
                    && evt.getNewValue() == SwingWorker.StateValue.DONE) {
                active.remove(worker);
            }
        });
        worker.execute();
    }

    public int activeCount() {
        return active.size();
    }

    /**
     * Cancels and interrupts everything in flight and refuses future work.
     *
     * @return the number of workers that were still running.
     */
    public int cancelAll() {
        shutdown = true;
        int cancelled = 0;
        for (SwingWorker<?, ?> worker : active) {
            if (worker.cancel(true)) {
                cancelled++;
            }
        }
        active.clear();
        return cancelled;
    }
}
