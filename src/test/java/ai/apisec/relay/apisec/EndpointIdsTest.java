package ai.apisec.relay.apisec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

final class EndpointIdsTest {

    @Test
    void encodesWorkedExample() {
        // GET:/workshop/api/shop/orders/all -> base64
        assertEquals("R0VUOi93b3Jrc2hvcC9hcGkvc2hvcC9vcmRlcnMvYWxs",
                EndpointIds.of("get", "/workshop/api/shop/orders/all"));
    }

    @Test
    void methodIsUppercasedBeforeEncoding() {
        // lower, mixed, and upper method all yield the same endpointId.
        String fromLower = EndpointIds.of("get", "/workshop/api/shop/orders/all");
        String fromMixed = EndpointIds.of("GeT", "/workshop/api/shop/orders/all");
        String fromUpper = EndpointIds.of("GET", "/workshop/api/shop/orders/all");
        assertEquals(fromLower, fromUpper);
        assertEquals(fromLower, fromMixed);
    }

    @Test
    void encodesTemplatizedPathExample() {
        // GET:/workshop/api/shop/orders/{order_id}
        assertEquals("R0VUOi93b3Jrc2hvcC9hcGkvc2hvcC9vcmRlcnMve29yZGVyX2lkfQ==",
                EndpointIds.of("get", "/workshop/api/shop/orders/{order_id}"));
    }

    @Test
    void differentMethodSamePathYieldsDifferentId() {
        assertNotEquals(EndpointIds.of("get", "/a"), EndpointIds.of("post", "/a"));
    }

    @Test
    void keyNormalizesCasingAndTrims() {
        assertEquals("GET:/a", EndpointIds.key("get", "/a"));
        assertEquals("GET:/a", EndpointIds.key("  GeT ", " /a "));
        assertNotEquals(EndpointIds.key("get", "/a"), EndpointIds.key("get", "/b"));
    }
}
