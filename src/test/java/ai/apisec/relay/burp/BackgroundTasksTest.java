package ai.apisec.relay.burp;

import org.junit.jupiter.api.Test;

import javax.swing.SwingWorker;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class BackgroundTasksTest {

    @Test
    void trackedWorkerIsRemovedOnceDone() throws Exception {
        BackgroundTasks tasks = new BackgroundTasks();
        CountDownLatch finished = new CountDownLatch(1);
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                return null;
            }

            @Override
            protected void done() {
                finished.countDown();
            }
        };

        tasks.execute(worker);

        assertTrue(finished.await(5, TimeUnit.SECONDS), "worker should complete");
        // done() runs on the EDT after the state flips; wait for the tracker to drain.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (tasks.activeCount() > 0 && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertEquals(0, tasks.activeCount(), "finished worker should be untracked");
    }

    @Test
    void cancelAllInterruptsABlockedWorker() throws Exception {
        BackgroundTasks tasks = new BackgroundTasks();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch interrupted = new CountDownLatch(1);
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                started.countDown();
                try {
                    // Simulates ScanPoller's sleep between poll attempts.
                    Thread.sleep(60_000L);
                } catch (InterruptedException ex) {
                    interrupted.countDown();
                }
                return null;
            }
        };

        tasks.execute(worker);
        assertTrue(started.await(5, TimeUnit.SECONDS), "worker should start");

        int cancelled = tasks.cancelAll();

        assertEquals(1, cancelled, "the blocked worker should be cancelled");
        assertTrue(interrupted.await(5, TimeUnit.SECONDS),
                "cancelAll must interrupt the worker thread so long sleeps abort");
        assertEquals(0, tasks.activeCount());
    }

    @Test
    void refusesNewWorkAfterShutdown() {
        BackgroundTasks tasks = new BackgroundTasks();
        tasks.cancelAll();

        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                return null;
            }
        };
        tasks.execute(worker);

        assertEquals(0, tasks.activeCount(), "no new workers after unload");
        assertEquals(SwingWorker.StateValue.PENDING, worker.getState(),
                "worker submitted after shutdown must never start");
    }
}
