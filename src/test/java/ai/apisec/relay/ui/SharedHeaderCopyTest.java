package ai.apisec.relay.ui;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

import static org.junit.jupiter.api.Assertions.*;

class SharedHeaderCopyTest {

    @Test
    void patLabelCarriesShortCredentialTooltip() {
        JLabel label = SharedHeader.patLabel();
        String tooltip = label.getToolTipText();

        assertEquals("PAT", label.getText());
        assertNotNull(tooltip);
        assertTrue(tooltip.contains("Saved in Burp preferences."));
        assertTrue(tooltip.contains("Clear PAT deletes it."));
        assertTrue(tooltip.contains("Write scope needed for Test set scans."));
        assertFalse(tooltip.contains("Stored by Burp"));
        assertFalse(tooltip.toLowerCase().contains("secure"));
        assertFalse(tooltip.toLowerCase().contains("encrypted"));
        assertFalse(tooltip.contains("mutates the selected APIsec application"));
        assertTrue(tooltip.length() <= 140);
    }

    @Test
    void introCopyUsesConciseLines() {
        String copy = SharedHeader.relayIntroText();
        String[] lines = copy.split("\\n");

        assertArrayEquals(new String[] {
                "Move findings from APIsec.ai to Burp for hands-on testing.",
                "Send curated requests back to APIsec for focused scans.",
                "Burp handles the attack work. APIsec keeps testing continuous."
        }, lines);
        for (String line : lines) {
            assertTrue(line.length() <= 72, line);
        }
        assertFalse(copy.contains("PAT is stored in Burp cross-project preferences"));
        assertFalse(copy.contains("APIsec Relay is a tool to easily migrate back and forth"));
    }

    @Test
    void configRowUsesPatLabelAndIntroCopy() {
        JPanel configRow = SharedHeader.buildConfigRowForTest();

        JLabel patLabel = findLabel(configRow, "PAT");
        JTextArea intro = findTextArea(configRow);

        assertNotNull(patLabel);
        assertNotNull(patLabel.getToolTipText());
        assertNotNull(intro);
        assertEquals(SharedHeader.relayIntroText(), intro.getText());
    }

    private static JLabel findLabel(Container root, String text) {
        for (Component component : root.getComponents()) {
            if (component instanceof JLabel label && text.equals(label.getText())) {
                return label;
            }
            if (component instanceof Container child) {
                JLabel found = findLabel(child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static JTextArea findTextArea(Container root) {
        for (Component component : root.getComponents()) {
            if (component instanceof JTextArea area) {
                return area;
            }
            if (component instanceof Container child) {
                JTextArea found = findTextArea(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
