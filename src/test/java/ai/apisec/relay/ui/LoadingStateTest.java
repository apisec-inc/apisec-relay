package ai.apisec.relay.ui;

import ai.apisec.relay.apisec.ApisecClient;
import ai.apisec.relay.apisec.model.ApplicationModels.AppDetail;
import ai.apisec.relay.apisec.model.ApplicationModels.AppItem;
import ai.apisec.relay.apisec.model.ApplicationModels.InstanceItem;
import ai.apisec.relay.apisec.model.AuthModels.AuthItem;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionsResponse;
import ai.apisec.relay.apisec.model.EndpointModels.EndpointItem;
import ai.apisec.relay.config.RelayConfig;
import ai.apisec.relay.testset.TestSet.StagedRequest;
import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class LoadingStateTest {

    @Test
    void sharedHeaderDisablesRefreshWhileApplicationsLoad() throws Exception {
        BlockingClient client = new BlockingClient();
        SharedHeader header = new SharedHeader(null, new RelayConfig(fakePreferences()), client);
        JButton refresh = button(header, "refreshButton");

        swing(refresh::doClick);
        assertTrue(client.applicationsStarted.await(2, TimeUnit.SECONDS));
        swing(() -> {
            assertFalse(refresh.isEnabled(), "refresh button should be disabled while refresh is running");
            assertTrue(refresh.getText().contains("Refreshing"), "refresh button should show loading text");
        });

        client.releaseApplications();
        flushEdt();
    }

    @Test
    void findingsPanelDisablesLoadButtonWhileFindingsLoad() throws Exception {
        BlockingClient client = new BlockingClient();
        SharedHeader header = headerWithSelection(client);
        RelayPanel panel = new RelayPanel(null, client, null, header);
        JButton load = button(panel, "loadButton");

        swing(load::doClick);
        assertTrue(client.findingsStarted.await(2, TimeUnit.SECONDS));
        swing(() -> {
            assertFalse(load.isEnabled(), "load findings button should be disabled while findings load");
            assertTrue(load.getText().contains("Loading"), "load findings button should show loading text");
        });

        client.releaseFindings();
        flushEdt();
    }

    @Test
    void testSetPanelDisablesLoadAuthsPreviewAndSubmitWhileAsyncRuns() throws Exception {
        BlockingClient authClient = new BlockingClient();
        SharedHeader authHeader = headerWithSelection(authClient);
        TestSetPanel authPanel = new TestSetPanel(null, authClient, authHeader, null);
        JButton authLoadAuths = button(authPanel, "loadAuthsButton");
        JButton authPreview = button(authPanel, "previewButton");
        JButton authSubmit = button(authPanel, "submitButton");

        swing(authLoadAuths::doClick);
        assertTrue(authClient.authsStarted.await(2, TimeUnit.SECONDS));
        swing(() -> {
            assertFalse(authLoadAuths.isEnabled(), "load auths should be disabled while auths load");
            assertFalse(authPreview.isEnabled(), "preview should be disabled while auths load");
            assertFalse(authSubmit.isEnabled(), "submit should be disabled while auths load");
            assertTrue(authLoadAuths.getText().contains("Loading"), "load auths should show loading text");
        });
        authClient.releaseAuths();
        flushEdt();

        BlockingClient previewClient = new BlockingClient();
        SharedHeader previewHeader = headerWithSelection(previewClient);
        TestSetPanel previewPanel = new TestSetPanel(null, previewClient, previewHeader, null);
        JButton previewLoadAuths = button(previewPanel, "loadAuthsButton");
        JButton previewButton = button(previewPanel, "previewButton");
        JButton previewSubmit = button(previewPanel, "submitButton");
        swing(() -> previewPanel.stage(List.of(new StagedRequest("GET", "/orders", "", "burp"))));
        swing(previewButton::doClick);
        assertTrue(previewClient.endpointsStarted.await(2, TimeUnit.SECONDS));
        swing(() -> {
            assertFalse(previewLoadAuths.isEnabled(), "load auths should be disabled while preview runs");
            assertFalse(previewButton.isEnabled(), "preview should be disabled while preview runs");
            assertFalse(previewSubmit.isEnabled(), "submit should be disabled while preview runs");
            assertTrue(previewButton.getText().contains("Previewing"), "preview should show loading text");
        });
        previewClient.releaseEndpoints();
        flushEdt();
    }

    private static SharedHeader headerWithSelection(BlockingClient client) throws Exception {
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

    private static JButton button(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return (JButton) f.get(target);
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

    private static Preferences fakePreferences() {
        return (Preferences) Proxy.newProxyInstance(
                Preferences.class.getClassLoader(),
                new Class<?>[]{Preferences.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getString" -> "apisec.relay.pat".equals(args[0]) ? "pat-for-test" : null;
                    case "setString", "deleteString" -> null;
                    default -> defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (type.equals(boolean.class)) {
            return false;
        }
        if (type.equals(int.class)) {
            return 0;
        }
        if (type.equals(long.class)) {
            return 0L;
        }
        return null;
    }

    private static void swing(Runnable r) throws Exception {
        SwingUtilities.invokeAndWait(r);
    }

    private static void flushEdt() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    private static final class BlockingClient extends ApisecClient {
        final CountDownLatch applicationsStarted = new CountDownLatch(1);
        final CountDownLatch releaseApplications = new CountDownLatch(1);
        final CountDownLatch findingsStarted = new CountDownLatch(1);
        final CountDownLatch releaseFindings = new CountDownLatch(1);
        final CountDownLatch authsStarted = new CountDownLatch(1);
        final CountDownLatch releaseAuths = new CountDownLatch(1);
        final CountDownLatch endpointsStarted = new CountDownLatch(1);
        final CountDownLatch releaseEndpoints = new CountDownLatch(1);

        BlockingClient() {
            super(null);
        }

        @Override
        public List<AppItem> listApplications() throws InterruptedException {
            applicationsStarted.countDown();
            releaseApplications.await(2, TimeUnit.SECONDS);
            return List.of();
        }

        @Override
        public AppDetail getApplication(String applicationId) {
            AppDetail detail = new AppDetail();
            detail.instances = List.of();
            return detail;
        }

        @Override
        public DetectionsResponse listDetections(String applicationId, String instanceId) throws InterruptedException {
            findingsStarted.countDown();
            releaseFindings.await(2, TimeUnit.SECONDS);
            return new DetectionsResponse();
        }

        @Override
        public List<AuthItem> listAuths(String applicationId, String instanceId) throws InterruptedException {
            authsStarted.countDown();
            releaseAuths.await(2, TimeUnit.SECONDS);
            return List.of();
        }

        @Override
        public List<EndpointItem> listEndpoints(String applicationId, String instanceId) throws InterruptedException {
            endpointsStarted.countDown();
            releaseEndpoints.await(2, TimeUnit.SECONDS);
            return List.of();
        }

        void releaseApplications() {
            releaseApplications.countDown();
        }

        void releaseFindings() {
            releaseFindings.countDown();
        }

        void releaseAuths() {
            releaseAuths.countDown();
        }

        void releaseEndpoints() {
            releaseEndpoints.countDown();
        }
    }
}
