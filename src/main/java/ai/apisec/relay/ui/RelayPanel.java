package ai.apisec.relay.ui;

import ai.apisec.relay.apisec.ApisecClient;
import ai.apisec.relay.apisec.model.ApplicationModels.AppItem;
import ai.apisec.relay.apisec.model.ApplicationModels.InstanceItem;
import ai.apisec.relay.apisec.model.DetectionModels.CategoryBlock;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionDetail;
import ai.apisec.relay.apisec.model.DetectionModels.DetectionsResponse;
import ai.apisec.relay.apisec.model.DetectionModels.TestResult;
import ai.apisec.relay.apisec.model.DetectionModels.VulnItem;
import ai.apisec.relay.burp.BackgroundTasks;
import ai.apisec.relay.burp.RepeaterDispatcher;
import ai.apisec.relay.testset.TestSet.StagedRequest;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Findings tab (read path). Application and instance come from the shared header;
 * this tab loads findings for the shared selection, lets the operator filter and
 * sort them (A3), shows Severity and OWASP from the list data (A2), and replays a
 * chosen finding's request chain into Repeater.
 */
public class RelayPanel extends JPanel {

    private final MontoyaApi api;
    private final ApisecClient client;
    private final RepeaterDispatcher dispatcher;
    private final SharedHeader header;
    private final BackgroundTasks tasks;

    private final FindingsTableModel tableModel = new FindingsTableModel();
    private final JTable table = new JTable(tableModel);
    private final TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(tableModel);
    private final JLabel status = new JLabel("Select an application and instance above, then Load findings.");
    private final JLabel countLabel = new JLabel("0 findings");
    private final JTextField filterField = new JTextField(20);
    private final JComboBox<String> statusFilter = new JComboBox<>();
    private final JButton loadButton = new JButton("Load findings");
    private final JComboBox<SeverityOption> severityFilter = new JComboBox<>(severityFilterOptions());
    private final JButton sendButton = new JButton("Send to Repeater");
    private final JCheckBox includeUnauthBox = new JCheckBox("Also send unauthenticated request", true);

    private static final String LOAD_ALL_FINDINGS = "Load All Findings";
    private static final List<String> SEVERITY_BUCKETS = List.of(
            "Critical", "High", "Medium", "Low", "Informational");

    private boolean loadingFindings = false;
    private boolean sendingToRepeater = false;
    private boolean updatingSeverityFilter = false;
    private java.util.function.Consumer<List<StagedRequest>> stageEndpointAction;

    public RelayPanel(MontoyaApi api, ApisecClient client, RepeaterDispatcher dispatcher,
                      SharedHeader header) {
        this(api, client, dispatcher, header, new BackgroundTasks());
    }

    public RelayPanel(MontoyaApi api, ApisecClient client, RepeaterDispatcher dispatcher,
                      SharedHeader header, BackgroundTasks tasks) {
        this.api = api;
        this.client = client;
        this.dispatcher = dispatcher;
        this.header = header;
        this.tasks = tasks == null ? new BackgroundTasks() : tasks;

        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 10, 10, 10));
        add(buildControls(), BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        // A3: sortable table. Severity sorts by numeric CVSS, not the label text.
        applyReadableRows(table);
        applyFindingsColumnWidths(table);
        table.setRowSorter(sorter);
        sorter.setComparator(FindingsTableModel.COL_SEVERITY, RelayPanel::compareSeverityValues);
        sorter.addRowSorterListener(e -> updateCount());

        // Untrusted finding fields must render as literal text, never HTML.
        HtmlSafe.hardenTable(table);
        HtmlSafe.harden(status);
        HtmlSafe.harden(countLabel);

        // A2: Severity cell shows "Qualifier (score)" while the model sorts by score.
        DefaultTableCellRenderer severityRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(
                        t, value, isSelected, hasFocus, row, column);
                FindingRow fr = tableModel.rowAt(t.convertRowIndexToModel(row));
                setText(fr == null ? "" : fr.severityLabel());
                return c;
            }
        };
        HtmlSafe.harden(severityRenderer);
        table.getColumnModel().getColumn(FindingsTableModel.COL_SEVERITY)
                .setCellRenderer(severityRenderer);

        header.addBusyListener(b -> updateActionState());
        installFindingsPopup();
        updateActionState();
    }

    /** A7: right-click a Findings row to stage its endpoint into the active test set. */
    public void setStageEndpointAction(java.util.function.Consumer<List<StagedRequest>> action) {
        this.stageEndpointAction = action;
    }

    private void installFindingsPopup() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem addToSet = new JMenuItem("Add to test set");
        addToSet.addActionListener(e -> onAddToTestSet());
        JMenuItem send = new JMenuItem("Send to Repeater");
        send.addActionListener(e -> onSendToRepeater());
        menu.add(addToSet);
        menu.add(send);
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mousePressed(java.awt.event.MouseEvent e) { maybePopup(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { maybePopup(e); }
            private void maybePopup(java.awt.event.MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow >= 0 && !table.isRowSelected(viewRow)) {
                    table.setRowSelectionInterval(viewRow, viewRow);
                }
                menu.show(table, e.getX(), e.getY());
            }
        });
    }

    private void onAddToTestSet() {
        if (stageEndpointAction == null) {
            setStatus("Test set staging is unavailable.");
            return;
        }
        int[] viewRows = table.getSelectedRows();
        if (viewRows.length == 0) {
            setStatus("Select one or more findings to add to the test set.");
            return;
        }
        List<StagedRequest> staged = new ArrayList<>();
        for (int viewRow : viewRows) {
            FindingRow row = tableModel.rowAt(table.convertRowIndexToModel(viewRow));
            if (row != null) {
                // Method + resource path; no captured body on a findings row.
                staged.add(new StagedRequest(row.method, row.resource, "", "findings"));
            }
        }
        if (staged.isEmpty()) {
            setStatus("No selected findings could be staged.");
            return;
        }
        stageEndpointAction.accept(staged);
        setStatus("Added " + staged.size() + " finding endpoint(s) to the active test set.");
    }

    private JComponent buildControls() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        loadButton.addActionListener(e -> onLoadFindings());
        p.add(loadButton);
        p.add(new JLabel("Severity"));
        severityFilter.setSelectedIndex(0);
        severityFilter.setRenderer(new SeverityOptionRenderer());
        severityFilter.setToolTipText("Choose which finding severities are shown after loading.");
        severityFilter.addActionListener(e -> onSeverityFilterChanged());
        p.add(severityFilter);

        filterField.setToolTipText("Matches across Method, Resource, Category, Test, and OWASP.");
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        p.add(filterField);
        p.add(new JLabel("Status"));
        statusFilter.addItem("All");
        statusFilter.addActionListener(e -> applyFilter());
        p.add(statusFilter);
        p.add(countLabel);
        return p;
    }

    private JComponent buildFooter() {
        JPanel p = new JPanel(new BorderLayout(8, 0));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        sendButton.addActionListener(e -> onSendToRepeater());
        actions.add(sendButton);
        actions.add(includeUnauthBox);
        p.add(actions, BorderLayout.WEST);
        p.add(status, BorderLayout.CENTER);
        return p;
    }

    private void onLoadFindings() {
        AppItem app = header.selectedApp();
        InstanceItem inst = header.selectedInstance();
        if (app == null || inst == null) {
            setStatus("Pick an application and instance in the header first.");
            return;
        }
        setStatus("Loading findings...");
        loadingFindings = true;
        setButtonLoading(loadButton, true, "Loading...");
        updateActionState();
        tasks.execute(new SwingWorker<List<FindingRow>, Void>() {
            @Override
            protected List<FindingRow> doInBackground() throws Exception {
                DetectionsResponse resp = client.listDetections(app.applicationId, inst.instanceId);
                return flatten(resp);
            }

            @Override
            protected void done() {
                try {
                    List<FindingRow> rows = get();
                    tableModel.setRows(rows);
                    rebuildStatusFilter(rows);
                    // A2: default sort by severity, highest first.
                    sorter.setSortKeys(List.of(
                            new RowSorter.SortKey(FindingsTableModel.COL_SEVERITY, SortOrder.DESCENDING)));
                    applyFilter();
                    setStatus("Loaded " + rows.size() + " findings.");
                } catch (java.util.concurrent.CancellationException ignored) {
                    // Cancelled on unload; nothing to update.
                } catch (Exception ex) {
                    fail("Failed to load findings", ex);
                } finally {
                    setButtonLoading(loadButton, false, null);
                    loadingFindings = false;
                    updateActionState();
                }
            }
        });
    }

    private void onSendToRepeater() {
        int[] viewRows = table.getSelectedRows();
        if (viewRows.length == 0) {
            setStatus("Select one or more findings first.");
            return;
        }
        List<FindingRow> rows = new ArrayList<>();
        for (int viewRow : viewRows) {
            FindingRow row = tableModel.rowAt(table.convertRowIndexToModel(viewRow));
            if (row != null) {
                rows.add(row);
            }
        }
        AppItem app = header.selectedApp();
        InstanceItem inst = header.selectedInstance();
        if (app == null || inst == null || rows.isEmpty()) {
            setStatus("Missing application, instance, or finding.");
            return;
        }
        setStatus("Fetching proof of concept...");
        sendingToRepeater = true;
        setButtonLoading(sendButton, true, "Sending...");
        updateActionState();
        tasks.execute(new SwingWorker<Integer, Void>() {
            @Override
            protected Integer doInBackground() throws Exception {
                int sent = 0;
                for (FindingRow row : rows) {
                    DetectionDetail detail = client.getDetection(
                            app.applicationId, inst.instanceId, row.detectionId);
                    sent += dispatcher.sendChain(detail, includeUnauthBox.isSelected());
                }
                return sent;
            }

            @Override
            protected void done() {
                try {
                    int sent = get();
                    if (sent == 0) {
                        setStatus("No replayable request found on selected finding(s).");
                    } else {
                        setStatus("Sent " + sent + " request(s) from " + rows.size() + " finding(s) to Repeater.");
                    }
                } catch (java.util.concurrent.CancellationException ignored) {
                    // Cancelled on unload; nothing to update.
                } catch (Exception ex) {
                    fail("Failed to send to Repeater", ex);
                } finally {
                    setButtonLoading(sendButton, false, null);
                    sendingToRepeater = false;
                    updateActionState();
                }
            }
        });
    }

    /** A3: filter across text columns plus the status dropdown. */
    private void applyFilter() {
        final String needle = filterField.getText() == null ? "" : filterField.getText().trim().toLowerCase();
        final String wantStatus = (String) statusFilter.getSelectedItem();
        final SeverityOption[] wantSeverity = currentSeverityOptions();
        sorter.setRowFilter(new RowFilter<FindingsTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends FindingsTableModel, ? extends Integer> entry) {
                FindingRow row = tableModel.rowAt(entry.getIdentifier());
                if (row == null) {
                    return false;
                }
                if (wantStatus != null && !"All".equals(wantStatus)
                        && !wantStatus.equalsIgnoreCase(row.statusValue)) {
                    return false;
                }
                if (!severityMatches(wantSeverity, row.severityBucket())) {
                    return false;
                }
                if (needle.isEmpty()) {
                    return true;
                }
                String hay = (row.method + " " + row.resource + " " + row.category + " "
                        + row.test + " " + row.owasp).toLowerCase();
                return hay.contains(needle);
            }
        });
        updateCount();
    }

    private void onSeverityFilterChanged() {
        if (updatingSeverityFilter) {
            return;
        }
        SeverityOption option = (SeverityOption) severityFilter.getSelectedItem();
        if (option == null) {
            return;
        }
        updatingSeverityFilter = true;
        try {
            if (option.selectsAll()) {
                boolean shouldSelectAll = !allSpecificSeveritiesSelected();
                for (int i = 0; i < severityFilter.getItemCount(); i++) {
                    severityFilter.getItemAt(i).setSelected(shouldSelectAll);
                }
            } else {
                option.setSelected(!option.selected());
                severityFilter.getItemAt(0).setSelected(allSpecificSeveritiesSelected());
            }
            severityFilter.repaint();
        } finally {
            updatingSeverityFilter = false;
        }
        applyFilter();
    }

    private boolean allSpecificSeveritiesSelected() {
        for (int i = 1; i < severityFilter.getItemCount(); i++) {
            if (!severityFilter.getItemAt(i).selected()) {
                return false;
            }
        }
        return true;
    }

    private SeverityOption[] currentSeverityOptions() {
        SeverityOption[] options = new SeverityOption[severityFilter.getItemCount()];
        for (int i = 0; i < severityFilter.getItemCount(); i++) {
            options[i] = severityFilter.getItemAt(i);
        }
        return options;
    }

    private void rebuildStatusFilter(List<FindingRow> rows) {
        String previous = (String) statusFilter.getSelectedItem();
        java.util.TreeSet<String> values = new java.util.TreeSet<>();
        for (FindingRow r : rows) {
            if (r.statusValue != null && !r.statusValue.isBlank()) {
                values.add(r.statusValue);
            }
        }
        statusFilter.removeAllItems();
        statusFilter.addItem("All");
        for (String v : values) {
            statusFilter.addItem(v);
        }
        if (previous != null) {
            statusFilter.setSelectedItem(previous);
        }
    }

    private void updateCount() {
        int shown = table.getRowCount();
        int total = tableModel.getRowCount();
        countLabel.setText(shown == total ? total + " findings" : shown + " of " + total + " findings");
    }

    private void updateActionState() {
        Runnable update = () -> {
            boolean headerBusy = header.isBusy();
            loadButton.setEnabled(!headerBusy && !loadingFindings && !sendingToRepeater);
            severityFilter.setEnabled(!headerBusy && !loadingFindings && !sendingToRepeater);
            sendButton.setEnabled(!headerBusy && !loadingFindings && !sendingToRepeater);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            update.run();
        } else {
            SwingUtilities.invokeLater(update);
        }
    }

    private void setButtonLoading(JButton button, boolean loading, String loadingText) {
        if (loading) {
            button.putClientProperty("relay.defaultText", button.getText());
            button.setText(loadingText);
            return;
        }
        Object defaultText = button.getClientProperty("relay.defaultText");
        if (defaultText instanceof String) {
            button.setText((String) defaultText);
        }
        button.putClientProperty("relay.defaultText", null);
    }

    private List<FindingRow> flatten(DetectionsResponse resp) {
        List<FindingRow> rows = new ArrayList<>();
        if (resp == null || resp.detections == null) {
            return rows;
        }
        for (CategoryBlock cat : resp.detections) {
            if (cat == null || cat.data == null || cat.data.vulnerabilities == null) {
                continue;
            }
            String categoryName = cat.category == null ? "" : nullSafe(cat.category.name);
            String testName = cat.test == null ? "" : nullSafe(cat.test.name);
            for (VulnItem v : cat.data.vulnerabilities) {
                if (v == null || v.detectionId == null) {
                    continue;
                }
                TestResult tr = v.testResult;
                Double score = tr == null ? null : tr.cvssScore;
                String qualifier = tr == null ? "" : nullSafe(tr.cvssQualifier);
                String owasp = tr == null ? "" : joinTags(tr.owaspTags);
                rows.add(new FindingRow(v.detectionId, v.endpointId, nullSafe(v.method).toUpperCase(),
                        nullSafe(v.resource), categoryName, testName, nullSafe(v.status),
                        score, qualifier, owasp));
            }
        }
        return rows;
    }

    private static String joinTags(List<String> tags) {
        if (tags == null || tags.isEmpty()) {
            return "";
        }
        return String.join(", ", tags);
    }

    private void fail(String prefix, Exception ex) {
        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
        api.logging().logToError(prefix + " :: " + cause.getMessage());
        setStatus(prefix + ": " + cause.getMessage());
    }

    private void setStatus(String text) {
        if (SwingUtilities.isEventDispatchThread()) {
            status.setText(text);
        } else {
            SwingUtilities.invokeLater(() -> status.setText(text));
        }
    }

    private static String nullSafe(String s) {
        return s == null ? "" : s;
    }

    // Row backing the findings table.
    private static final class FindingRow {
        final String detectionId;
        final String endpointId;
        final String method;
        final String resource;
        final String category;
        final String test;
        final String statusValue;
        final Double cvssScore;
        final String cvssQualifier;
        final String owasp;

        FindingRow(String detectionId, String endpointId, String method, String resource,
                   String category, String test, String statusValue,
                   Double cvssScore, String cvssQualifier, String owasp) {
            this.detectionId = detectionId;
            this.endpointId = endpointId;
            this.method = method;
            this.resource = resource;
            this.category = category;
            this.test = test;
            this.statusValue = statusValue;
            this.cvssScore = cvssScore;
            this.cvssQualifier = cvssQualifier;
            this.owasp = owasp;
        }

        /** "Medium (6)" / "Medium" / "6" / "" depending on what is present. */
        String severityLabel() {
            boolean hasQual = cvssQualifier != null && !cvssQualifier.isBlank();
            if (hasQual && cvssScore != null) {
                return cvssQualifier + " (" + formatScore(cvssScore) + ")";
            }
            if (hasQual) {
                return cvssQualifier;
            }
            return cvssScore == null ? "" : formatScore(cvssScore);
        }

        String severityBucket() {
            return RelayPanel.severityBucket(cvssQualifier, cvssScore);
        }
    }

    private static String formatScore(Double score) {
        if (score == null) {
            return "";
        }
        return score % 1 == 0 ? String.valueOf(score.intValue()) : String.valueOf(score);
    }

    static String defaultSeverityFilterLabel() {
        return LOAD_ALL_FINDINGS;
    }

    static SeverityOption[] severityFilterOptions() {
        SeverityOption[] options = new SeverityOption[SEVERITY_BUCKETS.size() + 1];
        options[0] = new SeverityOption(LOAD_ALL_FINDINGS, true, true);
        for (int i = 0; i < SEVERITY_BUCKETS.size(); i++) {
            options[i + 1] = new SeverityOption(SEVERITY_BUCKETS.get(i), true, false);
        }
        return options;
    }

    static List<String> selectedSeverityBuckets(SeverityOption[] options) {
        if (options == null || options.length == 0 || options[0].selected()) {
            return SEVERITY_BUCKETS;
        }
        List<String> selected = new ArrayList<>();
        for (SeverityOption option : options) {
            if (option != null && !option.selectsAll() && option.selected()) {
                selected.add(option.label());
            }
        }
        return selected;
    }

    static boolean severityMatches(SeverityOption[] options, String rowBucket) {
        return selectedSeverityBuckets(options).contains(rowBucket);
    }

    static String severityBucket(String qualifier, Double score) {
        String normalized = qualifier == null ? "" : qualifier.trim().toLowerCase();
        if (normalized.startsWith("crit")) {
            return "Critical";
        }
        if (normalized.startsWith("high")) {
            return "High";
        }
        if (normalized.startsWith("med")) {
            return "Medium";
        }
        if (normalized.startsWith("low")) {
            return "Low";
        }
        if (normalized.startsWith("info")) {
            return "Informational";
        }
        if (score == null) {
            return "Informational";
        }
        if (score >= 9.0) {
            return "Critical";
        }
        if (score >= 7.0) {
            return "High";
        }
        if (score >= 4.0) {
            return "Medium";
        }
        if (score > 0.0) {
            return "Low";
        }
        return "Informational";
    }

    static int compareSeverityValues(Object a, Object b) {
        double x = a instanceof Number ? ((Number) a).doubleValue() : -1.0;
        double y = b instanceof Number ? ((Number) b).doubleValue() : -1.0;
        return Double.compare(x, y);
    }

    static void applyReadableRows(JTable table) {
        int fontHeight = table.getFontMetrics(table.getFont()).getHeight();
        table.setRowHeight(Math.max(table.getRowHeight(), fontHeight + 8));
        table.setShowHorizontalLines(true);
        table.setIntercellSpacing(new Dimension(8, 4));
    }

    static void applyFindingsColumnWidths(JTable table) {
        int[] widths = {90, 70, 330, 220, 330, 90, 95};
        for (int i = 0; i < widths.length && i < table.getColumnModel().getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        if (table.getColumnModel().getColumnCount() > 0) {
            table.getColumnModel().getColumn(0).setMaxWidth(120);
        }
        if (table.getColumnModel().getColumnCount() > 1) {
            table.getColumnModel().getColumn(1).setMaxWidth(90);
        }
        if (table.getColumnModel().getColumnCount() > 5) {
            table.getColumnModel().getColumn(5).setMaxWidth(120);
        }
        if (table.getColumnModel().getColumnCount() > 6) {
            table.getColumnModel().getColumn(6).setMaxWidth(130);
        }
    }

    static final class SeverityOption {
        private final String label;
        private final boolean selectsAll;
        private boolean selected;

        SeverityOption(String label, boolean selected, boolean selectsAll) {
            this.label = label;
            this.selected = selected;
            this.selectsAll = selectsAll;
        }

        String label() {
            return label;
        }

        boolean selected() {
            return selected;
        }

        void setSelected(boolean selected) {
            this.selected = selected;
        }

        boolean selectsAll() {
            return selectsAll;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private static final class SeverityOptionRenderer extends JCheckBox implements ListCellRenderer<SeverityOption> {
        @Override
        public Component getListCellRendererComponent(JList<? extends SeverityOption> list, SeverityOption value,
                                                      int index, boolean isSelected, boolean cellHasFocus) {
            setText(value == null ? "" : value.label());
            setSelected(value != null && value.selected());
            setOpaque(true);
            setBackground(isSelected ? list.getSelectionBackground() : list.getBackground());
            setForeground(isSelected ? list.getSelectionForeground() : list.getForeground());
            setFont(list.getFont());
            return this;
        }
    }

    private static final class FindingsTableModel extends AbstractTableModel {
        static final int COL_SEVERITY = 0;
        private final String[] cols = {"Severity", "Method", "Resource", "Category", "Test", "OWASP", "Status"};
        private List<FindingRow> rows = new ArrayList<>();

        void setRows(List<FindingRow> rows) {
            this.rows = rows;
            fireTableDataChanged();
        }

        FindingRow rowAt(int i) {
            return (i >= 0 && i < rows.size()) ? rows.get(i) : null;
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int c) {
            return cols[c];
        }

        @Override
        public Class<?> getColumnClass(int c) {
            // Severity sorts numerically by CVSS; render via the comparator.
            return c == COL_SEVERITY ? Double.class : String.class;
        }

        @Override
        public Object getValueAt(int r, int c) {
            FindingRow row = rows.get(r);
            switch (c) {
                case 0: return row.cvssScore == null ? Double.valueOf(-1) : row.cvssScore;
                case 1: return row.method;
                case 2: return row.resource;
                case 3: return row.category;
                case 4: return row.test;
                case 5: return row.owasp;
                case 6: return row.statusValue;
                default: return "";
            }
        }
    }
}
