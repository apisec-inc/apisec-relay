package ai.apisec.relay.testset;

import ai.apisec.relay.testset.TestSet.StagedRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TestSetStoreTest {

    @Test
    void initializesFiveNamedSetsAndStartsOnFirstSet() {
        TestSetStore store = new TestSetStore();

        assertEquals(5, store.sets().size());
        assertEquals("Set 1", store.sets().get(0).getName());
        assertEquals("Set 5", store.sets().get(4).getName());
        assertEquals(0, store.activeIndex());
        assertEquals("Set 1", store.activeSet().getName());
    }

    @Test
    void stageTargetsOnlyTheActiveSet() {
        TestSetStore store = new TestSetStore();
        assertTrue(store.activeSet().add(new StagedRequest("GET", "/one", "", "r")));

        store.setActiveIndex(1);
        assertEquals(0, store.activeSet().size());
        assertTrue(store.activeSet().add(new StagedRequest("POST", "/two", "", "r")));

        assertEquals(1, store.sets().get(0).size());
        assertEquals("/one", store.sets().get(0).items().get(0).getPath());
        assertEquals(1, store.sets().get(1).size());
        assertEquals("/two", store.sets().get(1).items().get(0).getPath());
    }

    @Test
    void renamesOnlyTheSelectedSetAndRejectsBlankNames() {
        TestSetStore store = new TestSetStore();

        store.rename(2, "Regression smoke");

        assertEquals("Set 1", store.sets().get(0).getName());
        assertEquals("Regression smoke", store.sets().get(2).getName());
        assertThrows(IllegalArgumentException.class, () -> store.rename(2, "  "));
        assertEquals("Regression smoke", store.sets().get(2).getName());
    }

    @Test
    void removesAndClearsOnlyTheActiveSet() {
        TestSetStore store = new TestSetStore();
        StagedRequest first = new StagedRequest("GET", "/first", "", "r");
        store.activeSet().add(first);
        store.setActiveIndex(1);
        store.activeSet().add(new StagedRequest("GET", "/second", "", "r"));

        store.activeSet().clear();

        assertEquals(1, store.sets().get(0).size());
        assertEquals(0, store.sets().get(1).size());
        store.setActiveIndex(0);
        store.activeSet().remove(first);
        assertEquals(0, store.activeSet().size());
    }

    @Test
    void invalidActiveIndexIsRejected() {
        TestSetStore store = new TestSetStore();

        assertThrows(IndexOutOfBoundsException.class, () -> store.setActiveIndex(-1));
        assertThrows(IndexOutOfBoundsException.class, () -> store.setActiveIndex(5));
        assertEquals(0, store.activeIndex());
    }
}
