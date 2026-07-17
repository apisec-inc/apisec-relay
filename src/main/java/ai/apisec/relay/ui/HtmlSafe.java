package ai.apisec.relay.ui;

import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Swing renders any label text that begins with {@code <html>} as live markup.
 * Staged request paths and bodies, and finding fields, can carry content a
 * malicious site induced into proxy history, so rendering them through an
 * HTML-capable label would let that content reflow the UI or fetch a remote
 * image from inside Burp. Setting the {@code html.disable} client property on
 * the renderer forces literal text, honoring PortSwigger's rule that HTTP
 * message content is untrusted.
 */
final class HtmlSafe {

    private HtmlSafe() {
    }

    /** Marks a component so BasicHTML never parses its text as markup. */
    static void harden(JComponent component) {
        if (component != null) {
            component.putClientProperty("html.disable", Boolean.TRUE);
        }
    }

    /** A table cell renderer that renders every value as literal text. */
    static DefaultTableCellRenderer tableRenderer() {
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer();
        harden(renderer);
        return renderer;
    }

    /**
     * Forces literal rendering for the table's String/Object columns. Columns
     * that install their own renderer must harden it themselves.
     */
    static void hardenTable(JTable table) {
        table.setDefaultRenderer(Object.class, tableRenderer());
    }
}
