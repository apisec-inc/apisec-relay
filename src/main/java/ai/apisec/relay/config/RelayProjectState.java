package ai.apisec.relay.config;

import ai.apisec.relay.testset.TestSet;
import ai.apisec.relay.testset.TestSet.StagedRequest;
import ai.apisec.relay.testset.TestSetStore;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;
import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.List;

/**
 * Project-scoped extension state plus optional cross-project preferences.
 *
 * Project data stores the active application, instance, auth choice, active test
 * set index, and staged requests. Cross-project preferences store operator-owned
 * test set names when available, so names survive across Burp projects while the
 * staged request contents stay bound to the current project file.
 */
public final class RelayProjectState {
    public static final String NO_AUTH_SELECTION = "__apisec_relay_no_auth__";

    private static final String KEY_LAST_APP_ID = "apisec.relay.lastAppId";
    private static final String KEY_LAST_INSTANCE_ID = "apisec.relay.lastInstanceId";
    private static final String KEY_LAST_AUTH_ID = "apisec.relay.lastAuthId";
    private static final String KEY_ACTIVE_TEST_SET = "apisec.relay.activeTestSet";
    private static final String KEY_TEST_SETS = "apisec.relay.testSets";
    private static final String KEY_TEST_SET_NAMES = "apisec.relay.testSetNames";

    private final PersistedObject projectData;
    private final Preferences prefs;
    private final Gson gson = new Gson();

    public RelayProjectState(PersistedObject projectData) {
        this(projectData, null);
    }

    public RelayProjectState(PersistedObject projectData, Preferences prefs) {
        this.projectData = projectData;
        this.prefs = prefs;
    }

    public String lastAppId() {
        return blankToNull(projectData.getString(KEY_LAST_APP_ID));
    }

    public String lastInstanceId() {
        return blankToNull(projectData.getString(KEY_LAST_INSTANCE_ID));
    }

    public String lastAuthId() {
        return blankToNull(projectData.getString(KEY_LAST_AUTH_ID));
    }

    public void saveTargetSelection(String appId, String instanceId) {
        setOrDelete(KEY_LAST_APP_ID, appId);
        setOrDelete(KEY_LAST_INSTANCE_ID, instanceId);
    }

    public void saveAuthSelection(String authId) {
        setOrDelete(KEY_LAST_AUTH_ID, authId);
    }

    public void saveActiveTestSetIndex(int index) {
        if (index >= 0 && index < TestSetStore.SET_COUNT) {
            projectData.setInteger(KEY_ACTIVE_TEST_SET, index);
        }
    }

    public void saveTestSets(TestSetStore store) {
        saveTestSetNames(store);
        SavedStore saved = new SavedStore();
        for (TestSet set : store.sets()) {
            SavedSet out = new SavedSet();
            for (StagedRequest req : set.items()) {
                out.rows.add(new SavedRequest(req.getMethod(), req.getPath(), req.getBody(), req.getOrigin()));
            }
            saved.sets.add(out);
        }
        projectData.setString(KEY_TEST_SETS, gson.toJson(saved));
    }

    public void loadTestSets(TestSetStore store) {
        loadTestSetNames(store);
        SavedStore saved = parseStore(projectData.getString(KEY_TEST_SETS));
        if (saved != null && saved.sets != null) {
            int count = Math.min(saved.sets.size(), store.sets().size());
            for (int i = 0; i < count; i++) {
                SavedSet savedSet = saved.sets.get(i);
                TestSet set = store.sets().get(i);
                set.clear();
                if (savedSet != null && savedSet.rows != null) {
                    for (SavedRequest row : savedSet.rows) {
                        if (row != null) {
                            set.add(new StagedRequest(row.method, row.path, row.body, row.origin));
                        }
                    }
                }
            }
        }
        Integer active = projectData.getInteger(KEY_ACTIVE_TEST_SET);
        if (active != null && active >= 0 && active < store.sets().size()) {
            store.setActiveIndex(active);
        }
    }

    private void saveTestSetNames(TestSetStore store) {
        SavedNames names = new SavedNames();
        for (TestSet set : store.sets()) {
            names.names.add(set.getName());
        }
        nameStoreSet(gson.toJson(names));
    }

    private void loadTestSetNames(TestSetStore store) {
        SavedNames names = parseNames(nameStoreGet());
        if (names == null || names.names == null) {
            return;
        }
        int count = Math.min(names.names.size(), store.sets().size());
        for (int i = 0; i < count; i++) {
            String name = names.names.get(i);
            if (name != null && !name.isBlank()) {
                store.rename(i, name);
            }
        }
    }

    private String nameStoreGet() {
        if (prefs != null) {
            return prefs.getString(KEY_TEST_SET_NAMES);
        }
        return projectData.getString(KEY_TEST_SET_NAMES);
    }

    private void nameStoreSet(String value) {
        if (prefs != null) {
            prefs.setString(KEY_TEST_SET_NAMES, value);
        } else {
            projectData.setString(KEY_TEST_SET_NAMES, value);
        }
    }

    private void setOrDelete(String key, String value) {
        String cleaned = blankToNull(value);
        if (cleaned == null) {
            projectData.deleteString(key);
        } else {
            projectData.setString(key, cleaned);
        }
    }

    private SavedStore parseStore(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return gson.fromJson(json, SavedStore.class);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private SavedNames parseNames(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return gson.fromJson(json, SavedNames.class);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static String blankToNull(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        return s.trim();
    }

    private static final class SavedStore {
        List<SavedSet> sets = new ArrayList<>();
    }

    private static final class SavedSet {
        List<SavedRequest> rows = new ArrayList<>();
    }

    private static final class SavedNames {
        List<String> names = new ArrayList<>();
    }

    private static final class SavedRequest {
        String method;
        String path;
        String body;
        String origin;

        SavedRequest(String method, String path, String body, String origin) {
            this.method = method;
            this.path = path;
            this.body = body;
            this.origin = origin;
        }
    }
}
