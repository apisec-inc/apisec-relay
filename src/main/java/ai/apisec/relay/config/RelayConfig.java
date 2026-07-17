package ai.apisec.relay.config;

import burp.api.montoya.persistence.Preferences;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Host and PAT live in Burp's cross-project preferences so they survive across
 * projects and restarts. The PAT is a control-plane credential for the APIsec
 * management API, not target traffic.
 *
 * Note on placement: config is rendered inside the extension's own tab rather
 * than Burp's Settings dialog. That keeps v1 self-contained. Moving it to a
 * native settings panel later is a drop-in change against this same store.
 */
public class RelayConfig {

    private static final String KEY_HOST = "apisec.relay.host";
    private static final String KEY_PAT = "apisec.relay.pat";
    private static final String DEFAULT_HOST = "https://api.apisecapps.com";

    private final Preferences prefs;

    public RelayConfig(Preferences prefs) {
        this.prefs = prefs;
    }

    public String host() {
        String v = prefs.getString(KEY_HOST);
        if (v == null || v.isBlank()) {
            return DEFAULT_HOST;
        }
        try {
            // Re-validate on read: a value persisted by an older build could be
            // non-https. Fall back to the safe default rather than hand the PAT
            // to a cleartext or malformed host.
            return normalizeHost(v);
        } catch (IllegalArgumentException ex) {
            return DEFAULT_HOST;
        }
    }

    public String pat() {
        String v = prefs.getString(KEY_PAT);
        return v == null ? "" : v.trim();
    }

    /**
     * @throws IllegalArgumentException if the host is not a well-formed
     *     https:// URL. Nothing is persisted in that case.
     */
    public void save(String host, String pat) {
        prefs.setString(KEY_HOST, normalizeHost(host));
        if (pat == null || pat.isBlank()) {
            clearPat();
        } else {
            prefs.setString(KEY_PAT, pat.trim());
        }
    }

    public void clearPat() {
        prefs.deleteString(KEY_PAT);
    }

    /**
     * Validates and normalizes the APIsec host. The PAT rides every request as
     * a Bearer header, so plain http:// is rejected rather than silently sending
     * the credential in cleartext. A scheme-less value is assumed to be https.
     *
     * @return the normalized https URL, or the default host for blank input.
     * @throws IllegalArgumentException if the value cannot be used safely.
     */
    public static String normalizeHost(String host) {
        if (host == null || host.isBlank()) {
            return DEFAULT_HOST;
        }
        String candidate = host.trim();
        if (!candidate.contains("://")) {
            candidate = "https://" + candidate;
        }
        // Strip trailing slashes after the scheme is settled, so bare "https://"
        // cannot collapse into "https:" and get a second scheme prepended.
        candidate = candidate.replaceAll("/+$", "");
        URI uri;
        try {
            uri = new URI(candidate);
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("APIsec host is not a valid URL: " + host.trim());
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException(
                    "APIsec host must use https:// so the PAT is never sent in cleartext.");
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalArgumentException("APIsec host is missing a hostname: " + host.trim());
        }
        return candidate;
    }
}
