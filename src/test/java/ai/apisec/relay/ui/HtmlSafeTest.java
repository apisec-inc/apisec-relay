package ai.apisec.relay.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the "treat HTTP message content as untrusted" rule: an {@code <html>}
 * string reaching a hardened renderer must render as literal text, not markup.
 * BasicHTML stashes a parsed View under the client property "html" when it
 * treats text as markup, so that key staying null proves HTML was suppressed.
 */
final class HtmlSafeTest {

    private static final String HOSTILE = "<html><img src=\"http://attacker.example/x.png\"></html>";

    @Test
    void tableRendererDoesNotParseHtmlFromUntrustedCellValue() {
        JTable table = new JTable(new String[][]{{HOSTILE}}, new String[]{"Body"});
        DefaultTableCellRenderer renderer = HtmlSafe.tableRenderer();

        renderer.getTableCellRendererComponent(table, HOSTILE, false, false, 0, 0);

        assertEquals(Boolean.TRUE, renderer.getClientProperty("html.disable"));
        assertNull(renderer.getClientProperty("html"),
                "html.disable must stop BasicHTML from building a markup view");
        assertEquals(HOSTILE, renderer.getText(), "value must be shown verbatim");
    }

    @Test
    void plainLabelWouldParseHtml_provingTheGuardIsNecessary() {
        // Control: without hardening, the same value becomes a live HTML view.
        JLabel unguarded = new JLabel();
        unguarded.setText(HOSTILE);
        assertTrue(unguarded.getClientProperty("html") != null,
                "sanity: an unguarded label really does parse <html> content");
    }

    @Test
    void hardenSetsTheDisableProperty() {
        JLabel label = new JLabel();
        HtmlSafe.harden(label);
        label.setText(HOSTILE);
        assertEquals(Boolean.TRUE, label.getClientProperty("html.disable"));
        assertNull(label.getClientProperty("html"));
    }
}
