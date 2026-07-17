package ai.apisec.relay.ui;

import ai.apisec.relay.apisec.ApisecClient;
import ai.apisec.relay.apisec.model.EndpointModels.EndpointItem;
import ai.apisec.relay.testset.TestSet.StagedRequest;
import burp.api.montoya.MontoyaApi;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class TestSetPanelActiveSetTest {

    @Test
    void selectorChangesTheVisibleAndStagingActiveSet() throws Exception {
        TestSetPanel panel = new TestSetPanel((MontoyaApi) null, new FakeClient(), null, null);
        JComboBox<?> selector = combo(panel, "setCombo");

        swing(() -> panel.stage(List.of(new StagedRequest("GET", "/one", "", "burp"))));
        assertEquals(1, rowCount(panel));

        swing(() -> selector.setSelectedIndex(1));
        assertEquals(0, rowCount(panel));
        swing(() -> panel.stage(List.of(new StagedRequest("POST", "/two", "", "burp"))));
        assertEquals(1, rowCount(panel));

        swing(() -> selector.setSelectedIndex(0));
        assertEquals(1, rowCount(panel));
        assertEquals("/one", cell(panel, 0, 1));
        swing(() -> selector.setSelectedIndex(1));
        assertEquals("/two", cell(panel, 0, 1));
    }

    @Test
    void renamingActiveSetChangesSelectorLabel() throws Exception {
        TestSetPanel panel = new TestSetPanel((MontoyaApi) null, new FakeClient(), null, null);
        JComboBox<?> selector = combo(panel, "setCombo");

        swing(() -> panel.renameActiveSetForTest("Regression"));

        assertEquals("Regression", selector.getSelectedItem().toString());
    }

    private static int rowCount(TestSetPanel panel) throws Exception {
        JTable table = table(panel);
        return table.getModel().getRowCount();
    }

    private static Object cell(TestSetPanel panel, int row, int col) throws Exception {
        return table(panel).getModel().getValueAt(row, col);
    }

    private static JTable table(TestSetPanel panel) throws Exception {
        Field f = TestSetPanel.class.getDeclaredField("table");
        f.setAccessible(true);
        return (JTable) f.get(panel);
    }

    private static JComboBox<?> combo(TestSetPanel panel, String name) throws Exception {
        Field f = TestSetPanel.class.getDeclaredField(name);
        f.setAccessible(true);
        return (JComboBox<?>) f.get(panel);
    }

    private static void swing(Runnable r) throws Exception {
        SwingUtilities.invokeAndWait(r);
    }

    private static final class FakeClient extends ApisecClient {
        FakeClient() {
            super(null);
        }

        @Override
        public List<EndpointItem> listEndpoints(String applicationId, String instanceId) {
            return List.of();
        }
    }
}
