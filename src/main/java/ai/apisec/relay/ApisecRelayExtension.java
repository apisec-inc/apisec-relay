package ai.apisec.relay;

import ai.apisec.relay.apisec.ApisecClient;
import ai.apisec.relay.burp.BackgroundTasks;
import ai.apisec.relay.burp.RepeaterDispatcher;
import ai.apisec.relay.config.RelayConfig;
import ai.apisec.relay.config.RelayProjectState;
import ai.apisec.relay.ui.RelayPanel;
import ai.apisec.relay.ui.SharedHeader;
import ai.apisec.relay.ui.TestSetContextMenu;
import ai.apisec.relay.ui.TestSetPanel;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import java.awt.BorderLayout;
import java.awt.Font;
import java.util.function.IntConsumer;

/**
 * APIsec Relay.
 *
 * A shared header owns host/PAT and the single Application + Instance selection
 * that both sub-tabs read. Applications load automatically on initialize.
 *
 * Findings (read): pull a finding and drop its PoC request chain into Repeater.
 * Test set (write): right-click requests in Burp, stage them, dedup against the
 * instance, add the new endpoints, and start a scan — pushing coverage APIsec did
 * not have.
 */
public class ApisecRelayExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("APIsec Relay");

        RelayConfig config = new RelayConfig(api.persistence().preferences());
        RelayProjectState state = new RelayProjectState(
                api.persistence().extensionData(), api.persistence().preferences());
        ApisecClient client = new ApisecClient(api.logging(), api.http());
        RepeaterDispatcher dispatcher = new RepeaterDispatcher(api.repeater(), api.logging());
        BackgroundTasks tasks = new BackgroundTasks();
        api.extension().registerUnloadingHandler(() -> {
            int cancelled = tasks.cancelAll();
            api.logging().logToOutput("APIsec Relay unloaded. Cancelled "
                    + cancelled + " in-flight background task(s).");
        });

        SharedHeader header = new SharedHeader(api, config, client, state, tasks);
        RelayPanel readPanel = new RelayPanel(api, client, dispatcher, header, tasks);
        JTabbedPane tabs = new JTabbedPane();
        IntConsumer jumpToFindings = tabs::setSelectedIndex;
        TestSetPanel testSetPanel = new TestSetPanel(api, client, header, () -> jumpToFindings.accept(0), state, tasks);

        tabs.addTab("Findings", readPanel);
        tabs.addTab("Test Sets", testSetPanel);
        setStyledTabTitle(tabs, 0, "Findings");
        setStyledTabTitle(tabs, 1, "Test Sets");
        final int testSetTabIndex = 1;

        // A7: reflect the active staged count on the Test set tab label.
        testSetPanel.setStagedCountListener(count ->
                setStyledTabTitle(tabs, testSetTabIndex, count > 0 ? "Test Sets (" + count + ")" : "Test Sets"));
        testSetPanel.refreshStagedCount();

        // A7: let a Findings row be staged directly into the active test set.
        readPanel.setStageEndpointAction(testSetPanel::stage);

        JPanel root = new JPanel(new BorderLayout());
        root.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        root.add(header, BorderLayout.NORTH);
        root.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("APIsec Relay", root);

        // Context menu: stage selected requests into the Test set tab.
        api.userInterface().registerContextMenuItemsProvider(
                new TestSetContextMenu(testSetPanel::stage));

        // Auto-load applications once the UI is up (R4), off the EDT-blocking path.
        SwingUtilities.invokeLater(header::autoLoad);

        api.logging().logToOutput("APIsec Relay loaded. Shared target header + Findings + Test set active.");
    }

    static JLabel styledTabLabel(String title) {
        JLabel label = new JLabel(title, SwingConstants.CENTER);
        Font base = UIManager.getFont("TabbedPane.font");
        if (base == null) {
            base = label.getFont();
        }
        label.setFont(base.deriveFont(Font.BOLD, base.getSize2D() + 2.0f));
        label.setBorder(BorderFactory.createEmptyBorder(5, 14, 5, 14));
        return label;
    }

    static void setStyledTabTitle(JTabbedPane tabs, int index, String title) {
        java.awt.Component existing = tabs.getTabComponentAt(index);
        if (existing instanceof JLabel label) {
            label.setText(title);
        } else {
            tabs.setTabComponentAt(index, styledTabLabel(title));
        }
        tabs.setTitleAt(index, title);
    }
}
