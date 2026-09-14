package ai.apisec.relay.apisec;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.PortUnreachableException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Locale;

/**
 * Classifies a failure as an APIsec service-availability problem (the control
 * plane could not be reached at all) versus an application-level error (APIsec
 * answered with an HTTP error, rejected input, and so on).
 *
 * <p>The UI uses this to show a distinct "service unavailable" indicator and to
 * keep displaying the last successfully loaded applications/findings instead of
 * surfacing a raw transport error, which is especially helpful on restricted
 * networks or during an APIsec outage.
 *
 * <p>Pure and dependency-free so it is unit-testable without a Burp runtime.
 */
public final class ServiceHealth {

    private ServiceHealth() {
    }

    /**
     * Returns true when the throwable, or any exception in its cause chain,
     * looks like a connectivity/transport failure rather than a response the
     * server actually produced. HTTP status errors (for example "APIsec returned
     * HTTP 500") are intentionally treated as reachable, so they keep flowing
     * through the normal error path.
     */
    public static boolean isServiceUnavailable(Throwable t) {
        // Depth-bounded so a cyclic cause chain (a rare but possible pathology)
        // cannot spin forever.
        Throwable c = t;
        for (int depth = 0; c != null && depth < 32; depth++, c = c.getCause()) {
            if (c instanceof ConnectException
                    || c instanceof UnknownHostException
                    || c instanceof SocketTimeoutException
                    || c instanceof NoRouteToHostException
                    || c instanceof PortUnreachableException) {
                return true;
            }
            if (c instanceof IOException && messageLooksLikeTransport(c.getMessage())) {
                return true;
            }
        }
        return false;
    }

    private static boolean messageLooksLikeTransport(String message) {
        if (message == null) {
            return false;
        }
        String m = message.toLowerCase(Locale.ROOT);
        return m.contains("no http response")
                || m.contains("failed to connect")
                || m.contains("connection refused")
                || m.contains("connection reset")
                || m.contains("could not be reached")
                || m.contains("unable to connect")
                || m.contains("network is unreachable")
                || m.contains("timed out")
                || m.contains("timeout")
                || m.contains("unknown host")
                || m.contains("unavailable");
    }
}
