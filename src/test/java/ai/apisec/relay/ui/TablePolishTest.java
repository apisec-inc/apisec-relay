package ai.apisec.relay.ui;

import org.junit.jupiter.api.Test;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class TablePolishTest {

    @Test
    void readableRowsAddPaddingForLargeBurpFonts() {
        JTable table = new JTable(new DefaultTableModel(new Object[][]{{"a"}}, new Object[]{"A"}));
        int fontHeight = table.getFontMetrics(table.getFont()).getHeight();

        RelayPanel.applyReadableRows(table);

        assertTrue(table.getRowHeight() >= fontHeight + 8);
    }

    @Test
    void findingsColumnsGiveMostSpaceToResourceAndTest() {
        JTable table = new JTable(new DefaultTableModel(new Object[][]{{"", "", "", "", "", "", ""}},
                new Object[]{"Severity", "Method", "Resource", "Category", "Test", "OWASP", "Status"}));

        RelayPanel.applyFindingsColumnWidths(table);

        assertEquals(90, table.getColumnModel().getColumn(0).getPreferredWidth());
        assertEquals(70, table.getColumnModel().getColumn(1).getPreferredWidth());
        assertEquals(330, table.getColumnModel().getColumn(2).getPreferredWidth());
        assertEquals(330, table.getColumnModel().getColumn(4).getPreferredWidth());
        assertEquals(90, table.getColumnModel().getColumn(5).getPreferredWidth());
        assertEquals(95, table.getColumnModel().getColumn(6).getPreferredWidth());
    }

    @Test
    void testSetColumnsGiveMostSpaceToPath() {
        JTable table = new JTable(new DefaultTableModel(new Object[][]{{"", "", "", "", ""}},
                new Object[]{"Method", "Path", "Body", "Origin", "Status"}));

        TestSetPanel.applyStagedColumnWidths(table);

        assertEquals(70, table.getColumnModel().getColumn(0).getPreferredWidth());
        assertEquals(460, table.getColumnModel().getColumn(1).getPreferredWidth());
        assertEquals(260, table.getColumnModel().getColumn(2).getPreferredWidth());
        assertEquals(85, table.getColumnModel().getColumn(3).getPreferredWidth());
        assertEquals(100, table.getColumnModel().getColumn(4).getPreferredWidth());
    }
}
