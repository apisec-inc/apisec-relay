package ai.apisec.relay.config;

import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class RelayConfigTest {
    @Test
    void clearPatDeletesStoredPatWithoutChangingHost() {
        FakePreferences prefs = new FakePreferences();
        RelayConfig config = new RelayConfig(prefs);

        config.save("https://relay.apisec.example", "secret-pat-value");
        config.clearPat();

        assertEquals("https://relay.apisec.example", config.host());
        assertEquals("", config.pat());
        assertNull(prefs.getString("apisec.relay.pat"));
    }

    @Test
    void blankPatDeletesStoredPatInsteadOfSavingEmptySecret() {
        FakePreferences prefs = new FakePreferences();
        RelayConfig config = new RelayConfig(prefs);

        config.save("https://relay.apisec.example", "secret-pat-value");
        config.save("https://relay.apisec.example", "   ");

        assertEquals("https://relay.apisec.example", config.host());
        assertEquals("", config.pat());
        assertNull(prefs.getString("apisec.relay.pat"));
    }

    @Test
    void schemelessHostIsUpgradedToHttps() {
        assertEquals("https://relay.apisec.example",
                RelayConfig.normalizeHost("relay.apisec.example"));
    }

    @Test
    void trailingSlashesAreStripped() {
        assertEquals("https://relay.apisec.example",
                RelayConfig.normalizeHost("https://relay.apisec.example///"));
    }

    @Test
    void blankHostFallsBackToDefault() {
        assertEquals("https://api.apisecapps.com", RelayConfig.normalizeHost("   "));
        assertEquals("https://api.apisecapps.com", RelayConfig.normalizeHost(null));
    }

    @Test
    void plainHttpHostIsRejectedSoThePatIsNeverSentInCleartext() {
        assertThrows(IllegalArgumentException.class,
                () -> RelayConfig.normalizeHost("http://relay.apisec.example"));
    }

    @Test
    void malformedHostIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> RelayConfig.normalizeHost("https://exa mple.com"));
        assertThrows(IllegalArgumentException.class,
                () -> RelayConfig.normalizeHost("https://"));
    }

    @Test
    void hostReReadingUpgradesSchemelessAndFallsBackOnLegacyInsecureValue() {
        FakePreferences prefs = new FakePreferences();
        RelayConfig config = new RelayConfig(prefs);

        // Simulate a value written by an older build that skipped validation.
        prefs.setString("apisec.relay.host", "http://legacy.apisec.example");
        assertEquals("https://api.apisecapps.com", config.host());

        prefs.setString("apisec.relay.host", "relay.apisec.example");
        assertEquals("https://relay.apisec.example", config.host());
    }

    @Test
    void rejectedHostPersistsNothing() {
        FakePreferences prefs = new FakePreferences();
        RelayConfig config = new RelayConfig(prefs);

        assertThrows(IllegalArgumentException.class,
                () -> config.save("http://relay.apisec.example", "secret-pat-value"));

        assertNull(prefs.getString("apisec.relay.host"));
        assertNull(prefs.getString("apisec.relay.pat"));
    }

    private static final class FakePreferences implements Preferences {
        private final Map<String, String> strings = new HashMap<>();

        @Override
        public String getString(String key) {
            return strings.get(key);
        }

        @Override
        public void setString(String key, String value) {
            strings.put(key, value);
        }

        @Override
        public void deleteString(String key) {
            strings.remove(key);
        }

        @Override
        public Set<String> stringKeys() {
            return strings.keySet();
        }

        @Override
        public Boolean getBoolean(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setBoolean(String key, boolean value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteBoolean(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<String> booleanKeys() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Byte getByte(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setByte(String key, byte value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteByte(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<String> byteKeys() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Short getShort(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setShort(String key, short value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteShort(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<String> shortKeys() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Integer getInteger(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setInteger(String key, int value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteInteger(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<String> integerKeys() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Long getLong(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setLong(String key, long value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void deleteLong(String key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<String> longKeys() {
            throw new UnsupportedOperationException();
        }
    }
}
