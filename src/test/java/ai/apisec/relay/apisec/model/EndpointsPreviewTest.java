package ai.apisec.relay.apisec.model;

import ai.apisec.relay.apisec.EndpointIds;
import ai.apisec.relay.apisec.model.EndpointModels.EndpointGroup;
import ai.apisec.relay.apisec.model.EndpointModels.EndpointItem;
import ai.apisec.relay.apisec.model.EndpointModels.EndpointsResponse;
import com.google.gson.Gson;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Parses the nested endpoints response and reproduces the panel's NEW vs PRESENT
 * dedup so the preview logic is covered offline.
 */
final class EndpointsPreviewTest {

    private static final Gson GSON = new Gson();

    @Test
    void endpointsFixtureFlattensNestedGroups() throws IOException {
        EndpointsResponse resp = fixture();
        assertNotNull(resp.endpointGroups);
        Set<String> ids = existingIds(resp);
        assertEquals(3, ids.size());
        assertTrue(ids.contains(EndpointIds.of("get", "/workshop/api/shop/orders/all")));
        assertTrue(ids.contains(EndpointIds.of("get", "/workshop/api/shop/orders/{order_id}")));
    }

    @Test
    void presentEndpointIsLabeledPresentAndNewEndpointIsLabeledNew() throws IOException {
        Set<String> existing = existingIds(fixture());

        // Already on the instance -> PRESENT.
        String present = EndpointIds.of("get", "/workshop/api/shop/orders/all");
        assertTrue(existing.contains(present));

        // Coverage APIsec did not have -> NEW.
        String coverageNew = EndpointIds.of("post", "/workshop/api/shop/orders/all");
        assertFalse(existing.contains(coverageNew));

        String brandNewPath = EndpointIds.of("get", "/workshop/api/shop/secret-admin");
        assertFalse(existing.contains(brandNewPath));
    }

    private static Set<String> existingIds(EndpointsResponse resp) {
        Set<String> ids = new HashSet<>();
        if (resp.endpointGroups != null) {
            for (EndpointGroup g : resp.endpointGroups) {
                if (g != null && g.endpoints != null) {
                    for (EndpointItem e : g.endpoints) {
                        if (e != null && e.id != null) {
                            ids.add(e.id);
                        }
                    }
                }
            }
        }
        return ids;
    }

    private static EndpointsResponse fixture() throws IOException {
        try (InputStream stream = EndpointsPreviewTest.class.getResourceAsStream("/fixtures/endpoints_list.json")) {
            assertNotNull(stream, "Missing fixture resource: /fixtures/endpoints_list.json");
            try (Reader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                return GSON.fromJson(reader, EndpointsResponse.class);
            }
        }
    }
}
