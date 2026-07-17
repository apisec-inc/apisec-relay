package ai.apisec.relay.testset;

import ai.apisec.relay.apisec.EndpointIds;
import ai.apisec.relay.testset.TestSet.StagedRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TestSetTest {

    @Test
    void dedupsByMethodAndPathIgnoringCase() {
        TestSet set = new TestSet();
        assertTrue(set.add(new StagedRequest("GET", "/a", "", "sitemap")));
        // Same endpoint, different method casing and a body — still a duplicate.
        assertFalse(set.add(new StagedRequest("get", "/a", "x=1", "repeater")));
        assertEquals(1, set.size());
    }

    @Test
    void keepsDistinctEndpointsAndPreservesInsertionOrder() {
        TestSet set = new TestSet();
        set.add(new StagedRequest("GET", "/a", "", "s"));
        set.add(new StagedRequest("POST", "/a", "", "s"));
        set.add(new StagedRequest("GET", "/b", "", "s"));
        assertEquals(3, set.size());
        assertEquals("/a", set.items().get(0).getPath());
        assertEquals("POST", set.items().get(1).getMethod());
        assertEquals("/b", set.items().get(2).getPath());
    }

    @Test
    void reindexMergesRowsThatCollideAfterPathEdit() {
        TestSet set = new TestSet();
        set.add(new StagedRequest("GET", "/orders/123", "", "s"));
        set.add(new StagedRequest("GET", "/orders/456", "", "s"));
        assertEquals(2, set.size());
        // Operator templatizes both to the same path.
        for (StagedRequest r : set.items()) {
            r.setPath("/orders/{order_id}");
        }
        set.reindex();
        assertEquals(1, set.size());
        assertEquals("/orders/{order_id}", set.items().get(0).getPath());
    }

    @Test
    void endpointIdMatchesComputedKey() {
        StagedRequest r = new StagedRequest("get", "/workshop/api/shop/orders/all", "", "s");
        assertEquals(EndpointIds.of("GET", "/workshop/api/shop/orders/all"), r.endpointId());
    }

    @Test
    void removeAndClearWork() {
        TestSet set = new TestSet();
        StagedRequest a = new StagedRequest("GET", "/a", "", "s");
        set.add(a);
        set.add(new StagedRequest("GET", "/b", "", "s"));
        set.remove(a);
        assertEquals(1, set.size());
        set.clear();
        assertEquals(0, set.size());
    }
}
