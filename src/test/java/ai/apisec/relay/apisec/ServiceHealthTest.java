package ai.apisec.relay.apisec;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ServiceHealthTest {

    @Test
    void connectivityExceptionsAreServiceUnavailable() {
        assertTrue(ServiceHealth.isServiceUnavailable(new ConnectException("Connection refused")));
        assertTrue(ServiceHealth.isServiceUnavailable(new UnknownHostException("api.apisecapps.com")));
        assertTrue(ServiceHealth.isServiceUnavailable(new SocketTimeoutException("connect timed out")));
    }

    @Test
    void transportMessagesAreServiceUnavailable() {
        assertTrue(ServiceHealth.isServiceUnavailable(
                new IOException("APIsec request returned no HTTP response")));
        assertTrue(ServiceHealth.isServiceUnavailable(
                new IOException("Burp HTTP API is unavailable. Reload APIsec Relay in Burp.")));
    }

    @Test
    void unwrapsThroughTheCauseChain() {
        // SwingWorker.get() wraps the real failure in an ExecutionException.
        Throwable wrapped = new ExecutionException(new ConnectException("Connection refused"));
        assertTrue(ServiceHealth.isServiceUnavailable(wrapped));
    }

    @Test
    void httpStatusErrorsAreNotServiceUnavailable() {
        // APIsec answered, so this is reachable: it must stay on the normal path.
        assertFalse(ServiceHealth.isServiceUnavailable(new IOException("APIsec returned HTTP 500")));
        assertFalse(ServiceHealth.isServiceUnavailable(new IOException("APIsec returned HTTP 403")));
    }

    @Test
    void nullAndUnrelatedAreNotServiceUnavailable() {
        assertFalse(ServiceHealth.isServiceUnavailable(null));
        assertFalse(ServiceHealth.isServiceUnavailable(new IllegalArgumentException("bad name")));
    }

    @Test
    void cyclicCauseChainTerminates() {
        // A -> B -> A must not loop forever; neither is a transport error.
        IOException a = new IOException("APIsec returned HTTP 400");
        IOException b = new IOException("APIsec returned HTTP 401");
        a.initCause(b);
        b.initCause(a);
        assertFalse(ServiceHealth.isServiceUnavailable(a));
    }
}
