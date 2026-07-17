package ai.apisec.relay.apisec;

import ai.apisec.relay.apisec.model.ScanModels.NewEndpoint;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The write path must refuse to POST without an explicit per-call
 * {@link ApisecClient.WriteAuthorization}, so a mutating call can only happen
 * after the Test set panel mints one following user confirmation.
 */
final class ApisecClientWriteGateTest {

    private ApisecClient configuredClient() {
        ApisecClient client = new ApisecClient(null, null);
        client.configure("https://relay.apisec.example", "write-scoped-pat");
        return client;
    }

    @Test
    void addEndpointsWithoutAuthorizationIsRefusedBeforeAnyHttp() {
        ApisecClient client = configuredClient();
        List<NewEndpoint> endpoints = List.of(new NewEndpoint("get", "/api/v1/users", ""));

        IOException ex = assertThrows(IOException.class,
                () -> client.addEndpoints("app", "inst", endpoints, null));
        assertEquals("Write path is unauthorized. Confirm Test set submit before mutating APIsec.",
                ex.getMessage());
    }

    @Test
    void initiateScanWithoutAuthorizationIsRefusedBeforeAnyHttp() {
        ApisecClient client = configuredClient();

        IOException ex = assertThrows(IOException.class,
                () -> client.initiateScan("app", "inst", List.of("ZW5kcG9pbnRJZA=="), null, null));
        assertEquals("Write path is unauthorized. Confirm Test set submit before mutating APIsec.",
                ex.getMessage());
    }

    @Test
    void emptyEndpointListIsANoOpAndNeedsNoHttp() throws Exception {
        ApisecClient client = configuredClient();
        // No Http was supplied; a no-op add must return without attempting a send.
        client.addEndpoints("app", "inst", List.of(), client.authorizeWrite());
    }

    @Test
    void authorizeWriteMintsAUsableCapability() {
        ApisecClient client = configuredClient();
        assertNotNull(client.authorizeWrite());
    }
}
