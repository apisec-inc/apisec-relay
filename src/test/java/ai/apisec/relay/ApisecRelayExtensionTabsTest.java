package ai.apisec.relay;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.Font;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ApisecRelayExtensionTabsTest {

    @Test
    void styledTabLabelMakesTabsStandOut() {
        JLabel label = ApisecRelayExtension.styledTabLabel("Findings");
        Font base = UIManager.getFont("TabbedPane.font");

        assertEquals("Findings", label.getText());
        assertTrue(label.getFont().isBold(), "tab label should be bold");
        if (base != null) {
            assertTrue(label.getFont().getSize() > base.getSize(), "tab label should be larger than default tab font");
        }
        assertNotNull(label.getBorder(), "tab label should have padding so it reads as a tab");
    }

    @Test
    void styledTabTitleCanBeUpdatedWithoutLosingStyle() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Test Sets", new JPanel());

        ApisecRelayExtension.setStyledTabTitle(tabs, 0, "Test Sets");
        ApisecRelayExtension.setStyledTabTitle(tabs, 0, "Test Sets (3)");

        assertTrue(tabs.getTabComponentAt(0) instanceof JLabel);
        JLabel label = (JLabel) tabs.getTabComponentAt(0);
        assertEquals("Test Sets (3)", label.getText());
        assertTrue(label.getFont().isBold(), "updated tab label should stay bold");
    }
}
