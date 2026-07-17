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
import ai.apisec.relay.testset.TestSet.StagedRequest;
import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class RelayPanelFindingsStagingTest {

    @Test
    void addToTestSetStagesAllSelectedFindingRows() throws Exception {
        FindingsClient client = new FindingsClient();
        SharedHeader header = headerWithSelection(client);
        RelayPanel panel = new RelayPanel(null, client, null, header);
        List<StagedRequest> captured = new ArrayList<>();
        panel.setStageEndpointAction(captured::addAll);

        JButton loadButton = button(panel, "loadButton");
        swing(loadButton::doClick);
        assertTrue(client.findingsStarted.await(2, TimeUnit.SECONDS));
        flushEdt();
        Thread.sleep(100);
        flushEdt();
        JTable table = table(panel);
        assertEquals(2, table.getRowCount());
        swing(() -> table.setRowSelectionInterval(0, 1));

        Method add = RelayPanel.class.getDeclaredMethod("onAddToTestSet");
        add.setAccessible(true);
        swing(() -> {
            try {
                add.invoke(panel);
            } catch (ReflectiveOperationException ex) {
                throw new AssertionError(ex);
            }
        });

        assertEquals(2, captured.size());
        assertEquals("/one", captured.get(0).getPath());
        assertEquals("/two", captured.get(1).getPath());
    }

    @Test
    void sendToRepeaterSendsAllSelectedFindingRows() throws Exception {
        FindingsClient client = new FindingsClient();
        CapturingDispatcher dispatcher = new CapturingDispatcher(2);
        SharedHeader header = headerWithSelection(client);
        RelayPanel panel = new RelayPanel(null, client, dispatcher, header);

        JButton loadButton = button(panel, "loadButton");
        swing(loadButton::doClick);
        assertTrue(client.findingsStarted.await(2, TimeUnit.SECONDS));
        flushEdt();
        Thread.sleep(100);
        flushEdt();
        JTable table = table(panel);
        assertEquals(2, table.getRowCount());
        swing(() -> table.setRowSelectionInterval(0, 1));

        JButton sendButton = button(panel, "sendButton");
        swing(sendButton::doClick);

        assertTrue(dispatcher.sent.await(2, TimeUnit.SECONDS));
        assertEquals(2, dispatcher.count.get());
        assertEquals(List.of("det-1", "det-2"), client.requestedDetectionIds);
    }

    private static DetectionsResponse response() {
        DetectionsResponse resp = new DetectionsResponse();
        CategoryBlock block = new CategoryBlock();
        block.data = new DataBlock();
        block.data.vulnerabilities = new ArrayList<>();
        block.data.vulnerabilities.add(vuln("det-1", "GET", "/one"));
        block.data.vulnerabilities.add(vuln("det-2", "POST", "/two"));
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

    private static SharedHeader headerWithSelection(ApisecClient client) throws Exception {
        SharedHeader header = new SharedHeader(null, new RelayConfig(fakePreferences()), client);
        AppItem app = new AppItem();
        app.applicationId = "app-1";
        app.applicationName = "App One";
        InstanceItem inst = new InstanceItem();
        inst.instanceId = "inst-1";
        inst.hostUrl = "https://example.test";
        Field populating = SharedHeader.class.getDeclaredField("populating");
        populating.setAccessible(true);
        swing(() -> {
            try {
                populating.setBoolean(header, true);
                combo(header, "appCombo").addItem(app);
                combo(header, "appCombo").setSelectedItem(app);
                combo(header, "instanceCombo").addItem(inst);
                combo(header, "instanceCombo").setSelectedItem(inst);
            } catch (IllegalAccessException ex) {
                throw new AssertionError(ex);
            } finally {
                try {
                    populating.setBoolean(header, false);
                } catch (IllegalAccessException ex) {
                    throw new AssertionError(ex);
                }
            }
        });
        return header;
    }

    private static Preferences fakePreferences() {
        return (Preferences) Proxy.newProxyInstance(
                Preferences.class.getClassLoader(), new Class<?>[]{Preferences.class},
                (proxy, method, args) -> method.getReturnType().equals(boolean.class) ? false : null);
    }

    @SuppressWarnings("unchecked")
    private static JComboBox<Object> combo(Object target, String name) {
        try {
            Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return (JComboBox<Object>) f.get(target);
        } catch (ReflectiveOperationException ex) {
            throw new AssertionError(ex);
        }
    }

    private static JButton button(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return (JButton) f.get(target);
    }

    private static JTable table(RelayPanel panel) throws Exception {
        Field f = RelayPanel.class.getDeclaredField("table");
        f.setAccessible(true);
        return (JTable) f.get(panel);
    }

    private static void swing(Runnable r) throws Exception {
        SwingUtilities.invokeAndWait(r);
    }

    private static void flushEdt() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static final class FindingsClient extends ApisecClient {
        final CountDownLatch findingsStarted = new CountDownLatch(1);
        final List<String> requestedDetectionIds = new ArrayList<>();

        FindingsClient() {
            super(null);
        }

        @Override
        public DetectionsResponse listDetections(String applicationId, String instanceId) {
            findingsStarted.countDown();
            return response();
        }

        @Override
        public DetectionDetail getDetection(String applicationId, String instanceId, String detectionId) {
            requestedDetectionIds.add(detectionId);
            DetectionDetail detail = new DetectionDetail();
            detail.detectionId = detectionId;
            detail.resource = "det-1".equals(detectionId) ? "/one" : "/two";
            return detail;
        }
    }

    private static final class CapturingDispatcher extends RepeaterDispatcher {
        final AtomicInteger count = new AtomicInteger();
        final CountDownLatch sent;

        CapturingDispatcher(int expected) {
            super(null, null);
            this.sent = new CountDownLatch(expected);
        }

        @Override
        public int sendChain(DetectionDetail detail, boolean includeUnauthenticated) {
            count.incrementAndGet();
            sent.countDown();
            return 1;
        }
    }
}
