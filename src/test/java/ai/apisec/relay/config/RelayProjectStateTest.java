package ai.apisec.relay.config;

import ai.apisec.relay.testset.TestSet.StagedRequest;
import ai.apisec.relay.testset.TestSetStore;
import burp.api.montoya.persistence.PersistedObject;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

final class RelayProjectStateTest {

    @Test
    void persistsLastTargetAndAuthSelectionInProjectExtensionData() {
        Map<String, String> strings = new HashMap<>();
        Map<String, Integer> integers = new HashMap<>();
        RelayProjectState state = new RelayProjectState(fakeProjectData(strings, integers));

        state.saveTargetSelection("app-123", "inst-456");
        state.saveAuthSelection("auth-789");

        RelayProjectState restored = new RelayProjectState(fakeProjectData(strings, integers));
        assertEquals("app-123", restored.lastAppId());
        assertEquals("inst-456", restored.lastInstanceId());
        assertEquals("auth-789", restored.lastAuthId());
    }

    @Test
    void blankSelectionsDeleteProjectValues() {
        Map<String, String> strings = new HashMap<>();
        Map<String, Integer> integers = new HashMap<>();
        RelayProjectState state = new RelayProjectState(fakeProjectData(strings, integers));

        state.saveTargetSelection("app-123", "inst-456");
        state.saveAuthSelection("auth-789");
        state.saveTargetSelection(null, "");
        state.saveAuthSelection(null);

        assertNull(state.lastAppId());
        assertNull(state.lastInstanceId());
        assertNull(state.lastAuthId());
    }

    @Test
    void persistsActiveTestSetAndStagedRowsInProjectExtensionData() {
        Map<String, String> strings = new HashMap<>();
        Map<String, Integer> integers = new HashMap<>();
        RelayProjectState state = new RelayProjectState(fakeProjectData(strings, integers));
        TestSetStore store = new TestSetStore();
        store.setActiveIndex(1);
        store.activeSet().add(new StagedRequest("GET", "/one", "", "burp"));
        store.activeSet().add(new StagedRequest("POST", "/two", "{\"x\":1}", "burp"));

        state.saveActiveTestSetIndex(store.activeIndex());
        state.saveTestSets(store);

        TestSetStore restored = new TestSetStore();
        state.loadTestSets(restored);

        assertEquals(1, restored.activeIndex());
        assertEquals(2, restored.activeSet().size());
        assertEquals("/one", restored.activeSet().items().get(0).getPath());
        assertEquals("POST", restored.activeSet().items().get(1).getMethod());
        assertEquals("{\"x\":1}", restored.activeSet().items().get(1).getBody());
    }

    private static PersistedObject fakeProjectData(Map<String, String> strings, Map<String, Integer> integers) {
        return (PersistedObject) Proxy.newProxyInstance(
                RelayProjectStateTest.class.getClassLoader(),
                new Class<?>[]{PersistedObject.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    String key = args != null && args.length > 0 ? (String) args[0] : null;
                    switch (name) {
                        case "getString": return strings.get(key);
                        case "setString": strings.put(key, (String) args[1]); return null;
                        case "deleteString": strings.remove(key); return null;
                        case "stringKeys": return Set.copyOf(strings.keySet());
                        case "getInteger": return integers.get(key);
                        case "setInteger": integers.put(key, (Integer) args[1]); return null;
                        case "deleteInteger": integers.remove(key); return null;
                        case "integerKeys": return Set.copyOf(integers.keySet());
                        default: throw new UnsupportedOperationException(name);
                    }
                });
    }
}
