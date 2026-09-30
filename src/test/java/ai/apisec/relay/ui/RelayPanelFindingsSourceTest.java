package ai.apisec.relay.ui;

import ai.apisec.relay.apisec.ApisecClient;
import ai.apisec.relay.apisec.model.ApplicationModels.AppItem;
import ai.apisec.relay.apisec.model.ApplicationModels.InstanceItem;
import ai.apisec.relay.apisec.model.DetectionModels.CategoryBlock;
import ai.apisec.relay.apisec.model.DetectionModels.DataBlock;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionDetail;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionsResponse;
import ai.apisec.relay.apisec.model.DetectionModels.TestResult;
import ai.apisec.relay.apisec.model.DetectionModels.VulnItem;
import ai.apisec.relay.burp.RepeaterDispatcher;
import ai.apisec.relay.config.RelayConfig;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cached findings must stay tied to the host/application/instance they were
 * loaded from: a detection ID from instance A must never be replayed against
 * instance B, whether B's own load failed, the target changed mid-load, or the
 * host/PAT changed.
 */
final class RelayPanelFindingsSourceTest {

    private static final String PAT = "pat-secret-value";

    @Test
    void failedLoadForBKeepsACachedButBlocksReplayFromButtonAndMenu() throws Exception {
        Fixture f = new Fixture();
        f.select("app-A", "inst-A");
        f.loadAndWait();
        assertEquals(2, f.table().getRowCount());

        f.select("app-B", "inst-B");
        f.client.failListing = true;
        f.loadAndWait();

        // Cached findings from A stay viewable and are labelled with A.
        assertEquals(2, f.table().getRowCount());
        assertTrue(f.status().contains("cached finding(s) from"), f.status());
        assertTrue(f.status().contains("inst-A"), f.status());
        assertTrue(f.status().contains("Send to Repeater is disabled"), f.status());
        assertTrue(f.label("sourceLabel").contains("inst-A"), f.label("sourceLabel"));
        assertTrue(f.label("sourceLabel").contains("not the selected target"));

        JButton send = f.field("sendButton", JButton.class);
        JMenuItem menu = f.field("sendMenuItem", JMenuItem.class);
        assertFalse(send.isEnabled());
        assertFalse(menu.isEnabled());

        // Force both controls on to prove the handler enforces the check itself.
        swing(() -> f.table().setRowSelectionInterval(0, 1));
        swing(() -> { send.setEnabled(true); send.doClick(); });
        swing(() -> { menu.setEnabled(true); menu.doClick(); });
        f.invokeSend();
        flushWorkers();

        assertEquals(Collections.emptyList(), f.client.detectionRequests);
        assertTrue(f.status().contains("loaded from"), f.status());
        assertTrue(f.status().contains("inst-B"), f.status());
    }

    @Test
    void switchingBackToTheOriginalTargetRestoresReplayAgainstA() throws Exception {
        Fixture f = new Fixture();
        f.select("app-A", "inst-A");
        f.loadAndWait();
        f.select("app-B", "inst-B");
        f.client.failListing = true;
        f.loadAndWait();
        assertFalse(f.field("sendButton", JButton.class).isEnabled());

        f.select("app-A", "inst-A");
        assertTrue(f.field("sendButton", JButton.class).isEnabled());
        assertTrue(f.field("sendMenuItem", JMenuItem.class).isEnabled());
        assertTrue(f.status().contains("Header matches the loaded findings"), f.status());

        swing(() -> f.table().setRowSelectionInterval(0, 1));
        swing(() -> f.field("sendMenuItem", JMenuItem.class).doClick());
        assertTrue(f.dispatcher.sent.await(2, TimeUnit.SECONDS));
        flushWorkers();
        assertEquals(List.of("app-A/inst-A/det-A-1", "app-A/inst-A/det-A-2"), f.client.detectionRequests);
    }

    @Test
    void loadCompletingAfterTargetChangeIsDiscarded() throws Exception {
        Fixture f = new Fixture();
        f.select("app-A", "inst-A");
        f.client.holdListing = new CountDownLatch(1);
        f.clickLoad();
        assertTrue(f.client.listingStarted.await(2, TimeUnit.SECONDS));

        f.select("app-B", "inst-B");
        f.client.holdListing.countDown();
        flushWorkers();

        assertEquals(0, f.table().getRowCount());
        assertTrue(f.status().startsWith("Discarded findings loaded for"), f.status());
        assertFalse(f.field("sendButton", JButton.class).isEnabled());
        f.invokeSend();
        flushWorkers();
        assertEquals(Collections.emptyList(), f.client.detectionRequests);
    }

    @Test
    void loadCompletingAfterPatChangeIsDiscarded() throws Exception {
        Fixture f = new Fixture();
        f.select("app-A", "inst-A");
        f.client.holdListing = new CountDownLatch(1);
        f.clickLoad();
        assertTrue(f.client.listingStarted.await(2, TimeUnit.SECONDS));

        swing(() -> f.headerField("clearPatButton", JButton.class).doClick());
        f.client.holdListing.countDown();
        flushWorkers();

        assertEquals(0, f.table().getRowCount());
        assertTrue(f.status().startsWith("Discarded findings loaded for"), f.status());
    }

    @Test
    void clearingThePatInvalidatesCachedFindings() throws Exception {
        Fixture f = new Fixture();
        f.select("app-A", "inst-A");
        f.loadAndWait();
        assertEquals(2, f.table().getRowCount());

        swing(() -> f.headerField("clearPatButton", JButton.class).doClick());

        assertEquals(0, f.table().getRowCount());
        assertFalse(f.field("sendButton", JButton.class).isEnabled());
        assertTrue(f.status().contains("host or PAT changed"), f.status());
        assertFalse(f.status().contains(PAT));
        assertFalse(f.label("sourceLabel").contains(PAT));
        f.invokeSend();
        flushWorkers();
        assertEquals(Collections.emptyList(), f.client.detectionRequests);
    }

    @Test
    void changingThePatInvalidatesCachedFindings() throws Exception {
        Fixture f = new Fixture();
        f.select("app-A", "inst-A");
        f.loadAndWait();

        swing(() -> {
            f.headerField("patField", JPasswordField.class).setText("pat-rotated");
            f.headerField("saveButton", JButton.class).doClick();
        });
        flushWorkers();

        assertEquals(0, f.table().getRowCount());
        assertFalse(f.field("sendButton", JButton.class).isEnabled());
        assertFalse(f.status().contains("pat-rotated"));
        // Reselecting A under the new PAT still needs a fresh load.
        f.select("app-A", "inst-A");
        f.invokeSend();
        flushWorkers();
        assertEquals(Collections.emptyList(), f.client.detectionRequests);
    }

    @Test
    void changingTheHostInvalidatesCachedFindings() throws Exception {
        Fixture f = new Fixture();
        f.select("app-A", "inst-A");
        f.loadAndWait();

        swing(() -> {
            f.headerField("hostField", JTextField.class).setText("https://other.apisec.test");
            f.headerField("saveButton", JButton.class).doClick();
        });
        flushWorkers();

        assertEquals(0, f.table().getRowCount());
        f.select("app-A", "inst-A");
        assertFalse(f.field("sendButton", JButton.class).isEnabled());
        f.invokeSend();
        flushWorkers();
        assertEquals(Collections.emptyList(), f.client.detectionRequests);
    }

    @Test
    void savingUnchangedConfigKeepsCachedFindings() throws Exception {
        Fixture f = new Fixture();
        f.select("app-A", "inst-A");
        f.loadAndWait();

        assertEquals(2, f.table().getRowCount());
        swing(() -> f.headerField("saveButton", JButton.class).doClick());
        flushWorkers();
        // Refresh repopulates the header; reselect A and the cache is still valid.
        f.select("app-A", "inst-A");
        assertEquals(2, f.table().getRowCount());
        assertTrue(f.field("sendButton", JButton.class).isEnabled());
    }

    // ---- fixture ----

    private static final class Fixture {
        final ScriptedClient client = new ScriptedClient();
        final CapturingDispatcher dispatcher = new CapturingDispatcher(2);
        final SharedHeader header;
        final RelayPanel panel;

        Fixture() throws Exception {
            Map<String, String> store = new HashMap<>();
            store.put("apisec.relay.host", "https://api.apisec.test");
            store.put("apisec.relay.pat", PAT);
            MontoyaApi api = fakeApi();
            RelayConfig config = new RelayConfig(mapPreferences(store));
            client.configure(config.host(), config.pat());
            header = new SharedHeader(api, config, client);
            panel = new RelayPanel(api, client, dispatcher, header);
        }

        void select(String appId, String instId) throws Exception {
            AppItem app = new AppItem();
            app.applicationId = appId;
            app.applicationName = appId;
            InstanceItem inst = new InstanceItem();
            inst.instanceId = instId;
            inst.hostUrl = "https://" + instId + ".example.test";
            Field populating = SharedHeader.class.getDeclaredField("populating");
            populating.setAccessible(true);
            Method fire = SharedHeader.class.getDeclaredMethod("fireInstanceChanged");
            fire.setAccessible(true);
            swing(() -> {
                try {
                    JComboBox<Object> apps = headerCombo("appCombo");
                    JComboBox<Object> insts = headerCombo("instanceCombo");
                    populating.setBoolean(header, true);
                    apps.removeAllItems();
                    insts.removeAllItems();
                    apps.addItem(app);
                    apps.setSelectedItem(app);
                    insts.addItem(inst);
                    insts.setSelectedItem(inst);
                    populating.setBoolean(header, false);
                    fire.invoke(header);
                } catch (ReflectiveOperationException ex) {
                    throw new AssertionError(ex);
                }
            });
        }

        void clickLoad() throws Exception {
            swing(() -> field("loadButton", JButton.class).doClick());
        }

        void loadAndWait() throws Exception {
            clickLoad();
            flushWorkers();
        }

        void invokeSend() throws Exception {
            Method send = RelayPanel.class.getDeclaredMethod("onSendToRepeater");
            send.setAccessible(true);
            swing(() -> {
                try {
                    send.invoke(panel);
                } catch (ReflectiveOperationException ex) {
                    throw new AssertionError(ex);
                }
            });
        }

        JTable table() {
            return field("table", JTable.class);
        }

        String status() throws Exception {
            return label("status");
        }

        String label(String name) {
            String[] out = new String[1];
            try {
                swing(() -> out[0] = field(name, JLabel.class).getText());
            } catch (Exception ex) {
                throw new AssertionError(ex);
            }
            return out[0];
        }

        <T> T field(String name, Class<T> type) {
            return read(RelayPanel.class, panel, name, type);
        }

        <T> T headerField(String name, Class<T> type) {
            return read(SharedHeader.class, header, name, type);
        }

        @SuppressWarnings("unchecked")
        JComboBox<Object> headerCombo(String name) {
            return (JComboBox<Object>) headerField(name, JComboBox.class);
        }
    }

    private static <T> T read(Class<?> owner, Object target, String name, Class<T> type) {
        try {
            Field f = owner.getDeclaredField(name);
            f.setAccessible(true);
            return type.cast(f.get(target));
        } catch (ReflectiveOperationException ex) {
            throw new AssertionError(ex);
        }
    }

    private static DetectionsResponse findingsFor(String instanceId) {
        DetectionsResponse resp = new DetectionsResponse();
        CategoryBlock block = new CategoryBlock();
        block.data = new DataBlock();
        block.data.vulnerabilities = new ArrayList<>();
        String suffix = instanceId.substring(instanceId.length() - 1);
        block.data.vulnerabilities.add(vuln("det-" + suffix + "-1", "GET", "/one"));
        block.data.vulnerabilities.add(vuln("det-" + suffix + "-2", "POST", "/two"));
        resp.detections = List.of(block);
        return resp;
    }

    private static VulnItem vuln(String id, String method, String resource) {
        VulnItem v = new VulnItem();
        v.detectionId = id;
        v.method = method;
        v.resource = resource;
        v.status = "ACTIVE";
        v.testResult = new TestResult();
        v.testResult.cvssQualifier = "High";
        v.testResult.cvssScore = 7.5;
        return v;
    }

    private static Preferences mapPreferences(Map<String, String> store) {
        return (Preferences) Proxy.newProxyInstance(
                Preferences.class.getClassLoader(), new Class<?>[]{Preferences.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getString": return store.get((String) args[0]);
                        case "setString": store.put((String) args[0], (String) args[1]); return null;
                        case "deleteString": store.remove((String) args[0]); return null;
                        default: return method.getReturnType().equals(boolean.class) ? false : null;
                    }
                });
    }

    private static MontoyaApi fakeApi() {
        Logging logging = (Logging) Proxy.newProxyInstance(
                Logging.class.getClassLoader(), new Class<?>[]{Logging.class}, (p, m, a) -> null);
        return (MontoyaApi) Proxy.newProxyInstance(
                MontoyaApi.class.getClassLoader(), new Class<?>[]{MontoyaApi.class},
                (p, m, a) -> "logging".equals(m.getName()) ? logging : null);
    }

    private static void swing(Runnable r) throws Exception {
        SwingUtilities.invokeAndWait(r);
    }

    /** Lets background workers finish and their done() callbacks run on the EDT. */
    private static void flushWorkers() throws Exception {
        for (int i = 0; i < 5; i++) {
            SwingUtilities.invokeAndWait(() -> { });
            Thread.sleep(60);
        }
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static final class ScriptedClient extends ApisecClient {
        final List<String> detectionRequests = Collections.synchronizedList(new ArrayList<>());
        final CountDownLatch listingStarted = new CountDownLatch(1);
        volatile boolean failListing = false;
        volatile CountDownLatch holdListing;

        ScriptedClient() {
            super(null);
        }

        @Override
        public List<AppItem> listApplications() {
            return new ArrayList<>();
        }

        @Override
        public DetectionsResponse listDetections(String applicationId, String instanceId)
                throws IOException, InterruptedException {
            listingStarted.countDown();
            if (holdListing != null) {
                holdListing.await(2, TimeUnit.SECONDS);
            }
            if (failListing) {
                throw new IOException("APIsec request returned no HTTP response");
            }
            return findingsFor(instanceId);
        }

        @Override
        public DetectionDetail getDetection(String applicationId, String instanceId, String detectionId) {
            detectionRequests.add(applicationId + "/" + instanceId + "/" + detectionId);
            DetectionDetail detail = new DetectionDetail();
            detail.detectionId = detectionId;
            return detail;
        }
    }

    private static final class CapturingDispatcher extends RepeaterDispatcher {
        final CountDownLatch sent;

        CapturingDispatcher(int expected) {
            super(null, null);
            this.sent = new CountDownLatch(expected);
        }

        @Override
        public int sendChain(DetectionDetail detail, boolean includeUnauthenticated) {
            sent.countDown();
            return 1;
        }
    }
}
