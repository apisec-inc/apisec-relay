package ai.apisec.relay.ui;

import ai.apisec.relay.apisec.ApisecClient;
import ai.apisec.relay.apisec.ScanPoller;
import ai.apisec.relay.apisec.model.ApplicationModels.AppItem;
import ai.apisec.relay.apisec.model.ApplicationModels.InstanceItem;
import ai.apisec.relay.apisec.model.AuthModels.AuthItem;
import ai.apisec.relay.apisec.model.EndpointModels.EndpointItem;
import ai.apisec.relay.apisec.model.ScanModels.NewEndpoint;
import ai.apisec.relay.apisec.model.ScanModels.ScanStatus;
import ai.apisec.relay.burp.BackgroundTasks;
import ai.apisec.relay.config.RelayProjectState;
import ai.apisec.relay.testset.PathTemplatizer;
import ai.apisec.relay.testset.TestSet;
import ai.apisec.relay.testset.TestSet.StagedRequest;
import ai.apisec.relay.testset.TestSetStore;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Staging table + submit flow for pushing Burp-discovered coverage into APIsec.
 *
 * Application and instance come from the shared header. Scan auth lives here
 * because it is write-only; the picker always offers an explicit "No auth" entry
 * for an unauthenticated scan. Operator stages requests via the context menu,
 * optionally templatizes paths, previews NEW vs PRESENT, then submits: add the
 * NEW endpoints and scan the full staged set. A confirm dialog is mandatory.
 */
public final class TestSetPanel extends JPanel {

    /** Sentinel shown at the top of the auth picker for an unauthenticated scan. */
    private static final AuthItem NO_AUTH = noAuthSentinel();

    private final MontoyaApi api;
    private final ApisecClient client;
    private final SharedHeader header;
    private final Runnable jumpToFindings;
    private final ScanPoller scanPoller;
    private final RelayProjectState state;
    private final BackgroundTasks tasks;

    private final TestSetStore testSets = new TestSetStore();
    private final StagedTableModel tableModel = new StagedTableModel();
    private final JTable table = new JTable(tableModel);

    private final JComboBox<TestSet> setCombo = new JComboBox<>();
    private final JButton renameSetButton = new JButton("Rename set");
    private final JComboBox<AuthItem> authCombo = new JComboBox<>();
    private final JButton loadAuthsButton = new JButton("Refresh auths");
    private final JButton removeButton = new JButton("Remove selected");
    private final JButton clearButton = new JButton("Clear");
    private final JButton templatizeButton = new JButton("Template paths");
    private final JButton previewButton = new JButton("Preview NEW/PRESENT");
    private final JButton submitButton = new JButton("Submit and scan");
    private final JButton cancelButton = new JButton("Cancel");
    private final JButton jumpToFindingsButton = new JButton("Jump to Findings tab");
    private final JLabel status = new JLabel("Right-click requests in Burp and choose 'APIsec Relay: Add to test set'.");

    private boolean busy = false;
    private boolean populatingAuths = false;
    private JButton busyButton;
    private SwingWorker<?, ?> activeWorker;
    private java.util.function.IntConsumer stagedCountListener;

    public TestSetPanel(MontoyaApi api, ApisecClient client, SharedHeader header, Runnable jumpToFindings) {
        this(api, client, header, jumpToFindings, new ScanPoller(), null, null);
    }

    public TestSetPanel(MontoyaApi api, ApisecClient client, SharedHeader header,
                        Runnable jumpToFindings, RelayProjectState state) {
        this(api, client, header, jumpToFindings, new ScanPoller(), state, null);
    }

    public TestSetPanel(MontoyaApi api, ApisecClient client, SharedHeader header,
                        Runnable jumpToFindings, RelayProjectState state, BackgroundTasks tasks) {
        this(api, client, header, jumpToFindings, new ScanPoller(), state, tasks);
    }

    TestSetPanel(MontoyaApi api, ApisecClient client, SharedHeader header,
                 Runnable jumpToFindings, ScanPoller scanPoller) {
        this(api, client, header, jumpToFindings, scanPoller, null, null);
    }

    TestSetPanel(MontoyaApi api, ApisecClient client, SharedHeader header,
                 Runnable jumpToFindings, ScanPoller scanPoller, RelayProjectState state) {
        this(api, client, header, jumpToFindings, scanPoller, state, null);
    }

    TestSetPanel(MontoyaApi api, ApisecClient client, SharedHeader header,
                 Runnable jumpToFindings, ScanPoller scanPoller, RelayProjectState state,
                 BackgroundTasks tasks) {
        this.api = api;
        this.client = client;
        this.header = header;
        this.jumpToFindings = jumpToFindings == null ? () -> { } : jumpToFindings;
        this.scanPoller = scanPoller == null ? new ScanPoller() : scanPoller;
        this.state = state;
        this.tasks = tasks == null ? new BackgroundTasks() : tasks;
        if (state != null) {
            state.loadTestSets(testSets);
        }

        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 10, 10, 10));
        RelayPanel.applyReadableRows(table);
        applyStagedColumnWidths(table);
        // Staged paths/bodies come from target traffic; render them literally.
        HtmlSafe.hardenTable(table);
        HtmlSafe.harden(status);
        add(buildTargets(), BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        installTablePopup();

        // A9: when the shared instance changes, auto-fetch this instance's auths
        // and refill the picker (No auth stays at top). Load auths remains as a
        // manual refresh. resetAuths runs first to clear stale entries.
        if (header != null) {
            header.addInstanceChangeListener(this::onInstanceChanged);
            header.addBusyListener(b -> updateActionState());
        }

        resetAuths();
        updateActionState();
    }

    private JComponent buildTargets() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        p.add(new JLabel("Test set"));
        for (TestSet set : testSets.sets()) {
            setCombo.addItem(set);
        }
        setCombo.setSelectedIndex(testSets.activeIndex());
        setCombo.addActionListener(e -> onSetSelected());
        // D4: size to a long name and show the full value on hover.
        sizeCombo(setCombo, 200);
        setCombo.setRenderer(new TooltipRenderer("Select a test set"));
        p.add(setCombo);
        renameSetButton.addActionListener(e -> onRenameSet());
        p.add(renameSetButton);
        p.add(new JLabel("  |  "));
        p.add(new JLabel("Scan auth"));
        // D4: wide enough to read instance auth names like "Crapi-Test909".
        sizeCombo(authCombo, 200);
        authCombo.setRenderer(new TooltipRenderer("Select scan auth"));
        p.add(authCombo);
        loadAuthsButton.addActionListener(e -> onLoadAuths());
        loadAuthsButton.setToolTipText(refreshAuthsTooltip());
        p.add(loadAuthsButton);
        authCombo.addActionListener(e -> saveAuthSelection());
        // C1: hint removed; the dropdown already reads "No auth".
        return p;
    }

    /** D4: give a combo a readable minimum width. */
    private static void sizeCombo(JComboBox<?> combo, int minWidth) {
        Dimension pref = combo.getPreferredSize();
        int width = Math.max(minWidth, pref.width);
        combo.setPreferredSize(new Dimension(width, pref.height));
        combo.setMaximumSize(new Dimension(width, pref.height));
    }

    static String refreshAuthsTooltip() {
        return "Reload scan auths from the selected APIsec instance.";
    }

    static String templatizeTooltip() {
        return "Convert concrete values like /orders/123 or ?id=5 into APIsec path templates.";
    }

    static String previewTooltip() {
        return "Check staged requests against APIsec and mark each as NEW vs PRESENT before submitting.";
    }

    static String jumpToFindingsTooltip() {
        return "Switch to the Findings tab after a submitted scan completes.";
    }

    static void applyStagedColumnWidths(JTable table) {
        int[] widths = {70, 460, 260, 85, 100};
        for (int i = 0; i < widths.length && i < table.getColumnModel().getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        if (table.getColumnModel().getColumnCount() > 0) {
            table.getColumnModel().getColumn(0).setMaxWidth(90);
        }
        if (table.getColumnModel().getColumnCount() > 3) {
            table.getColumnModel().getColumn(3).setMaxWidth(100);
        }
        if (table.getColumnModel().getColumnCount() > 4) {
            table.getColumnModel().getColumn(4).setMaxWidth(130);
        }
    }

    private JComponent buildFooter() {
        JPanel p = new JPanel(new BorderLayout(8, 4));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        removeButton.addActionListener(e -> onRemoveSelected());
        clearButton.addActionListener(e -> onClear());
        previewButton.addActionListener(e -> onPreview());
        submitButton.addActionListener(e -> onSubmit());
        cancelButton.addActionListener(e -> onCancel());
        cancelButton.setEnabled(false);
        cancelButton.setToolTipText("Stop the running request, including a long scan poll.");
        jumpToFindingsButton.addActionListener(e -> this.jumpToFindings.run());
        jumpToFindingsButton.setEnabled(false);
        submitButton.setToolTipText("Adds NEW endpoints to the instance and starts a scan over the staged set. "
                + "Mutates the APIsec project; you will be asked to confirm.");
        previewButton.setToolTipText(previewTooltip());
        jumpToFindingsButton.setToolTipText(jumpToFindingsTooltip());
        buttons.add(removeButton);
        buttons.add(clearButton);
        templatizeButton.addActionListener(e -> onTemplatizeSelected());
        templatizeButton.setToolTipText(templatizeTooltip());
        buttons.add(templatizeButton);
        buttons.add(new JLabel("  |  "));
        buttons.add(previewButton);
        buttons.add(submitButton);
        buttons.add(cancelButton);
        buttons.add(jumpToFindingsButton);
        p.add(buttons, BorderLayout.WEST);
        p.add(status, BorderLayout.SOUTH);
        return p;
    }

    /** Auth picker resets to just the No-auth sentinel; explicit choice required. */
    private void resetAuths() {
        Runnable r = () -> {
            populatingAuths = true;
            try {
                authCombo.removeAllItems();
                authCombo.addItem(NO_AUTH);
                authCombo.setSelectedIndex(-1);
            } finally {
                populatingAuths = false;
            }
            updateActionState();
        };
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }

    // ---- staging entry point, called from the context menu (any thread) ----

    /** A7: notified with the active set's staged count whenever it changes. */
    public void setStagedCountListener(java.util.function.IntConsumer listener) {
        this.stagedCountListener = listener;
    }

    /** A7: push the current active-set count to the tab-label listener. */
    public void refreshStagedCount() {
        if (stagedCountListener != null) {
            int n = activeSet().size();
            if (SwingUtilities.isEventDispatchThread()) {
                stagedCountListener.accept(n);
            } else {
                SwingUtilities.invokeLater(() -> stagedCountListener.accept(n));
            }
        }
    }

    /** A7: stage a single request (used by the Findings "Add to test set" action). */
    public void stageOne(StagedRequest request) {
        stage(List.of(request));
    }

    public void stage(List<StagedRequest> requests) {
        Runnable r = () -> {
            int added = 0;
            for (StagedRequest req : requests) {
                if (activeSet().add(req)) {
                    added++;
                }
            }
            persistTestSets();
            tableModel.fireTableDataChanged();
            refreshStagedCount();
            int dupes = requests.size() - added;
            setStatus("Staged " + added + " request(s) into " + activeSet().getName()
                    + (dupes > 0 ? ", " + dupes + " duplicate(s) skipped." : ".")
                    + " Total: " + activeSet().size() + ".");
        };
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }

    // ---- auth loading ----

    /** A9: instance changed — clear stale auths, then auto-load if an instance is set. */
    private void onInstanceChanged() {
        resetAuths();
        if (header != null && header.selectedApp() != null && header.selectedInstance() != null) {
            loadAuths(true);
        }
    }

    private void onLoadAuths() {
        loadAuths(false);
    }

    private void loadAuths(boolean auto) {
        AppItem app = header.selectedApp();
        InstanceItem inst = header.selectedInstance();
        if (app == null || inst == null) {
            if (!auto) {
                setStatus("Pick an application and instance in the header first.");
            }
            return;
        }
        setStatus(auto ? "Instance changed. Loading scan auths..." : "Refreshing scan auths...");
        startBusy(loadAuthsButton, "Loading auths...");
        runTracked(new SwingWorker<List<AuthItem>, Void>() {
            @Override
            protected List<AuthItem> doInBackground() throws Exception {
                return client.listAuths(app.applicationId, inst.instanceId);
            }

            @Override
            protected void done() {
                try {
                    List<AuthItem> auths = get();
                    populatingAuths = true;
                    try {
                        authCombo.removeAllItems();
                        authCombo.addItem(NO_AUTH);
                        for (AuthItem a : auths) {
                            authCombo.addItem(a);
                        }
                    } finally {
                        populatingAuths = false;
                    }
                    restoreAuthSelection();
                    setStatus("Loaded " + auths.size() + " auth(s). Pick one, or 'No auth' for an unauthenticated scan.");
                } catch (java.util.concurrent.CancellationException ignored) {
                    // Cancelled on unload; nothing to update.
                } catch (Exception ex) {
                    fail("Failed to load auths", ex);
                } finally {
                    finishBusy();
                }
            }
        });
    }

    // ---- preview ----

    private void onPreview() {
        AppItem app = header.selectedApp();
        InstanceItem inst = header.selectedInstance();
        if (app == null || inst == null) {
            setStatus("Pick an application and instance in the header to preview against.");
            return;
        }
        if (activeSet().size() == 0) {
            setStatus("Nothing staged to preview.");
            return;
        }
        stopEditing();
        activeSet().reindex();
        persistTestSets();
        setStatus("Computing NEW vs PRESENT against the instance...");
        startBusy(previewButton, "Previewing...");
        runTracked(new SwingWorker<Set<String>, Void>() {
            @Override
            protected Set<String> doInBackground() throws Exception {
                List<EndpointItem> existing = client.listEndpoints(app.applicationId, inst.instanceId);
                Set<String> ids = new HashSet<>();
                for (EndpointItem e : existing) {
                    if (e != null && e.id != null) {
                        ids.add(e.id);
                    }
                }
                return ids;
            }

            @Override
            protected void done() {
                try {
                    Set<String> existingIds = get();
                    int neu = 0;
                    int present = 0;
                    for (StagedRequest req : activeSet().items()) {
                        boolean isPresent = existingIds.contains(req.endpointId());
                        tableModel.setLabel(req, isPresent ? "PRESENT" : "NEW");
                        if (isPresent) {
                            present++;
                        } else {
                            neu++;
                        }
                    }
                    tableModel.fireTableDataChanged();
                    int total = neu + present;
                    String instName = inst == null ? activeSet().getName() : String.valueOf(inst);
                    setStatus("Preview: " + neu + " NEW, " + present + " PRESENT. Submit "
                            + plural(neu, "adds %d new endpoint", "adds %d new endpoints")
                            + ", " + plural(total, "scans %d endpoint", "scans %d endpoints")
                            + " in " + instName + ".");
                } catch (java.util.concurrent.CancellationException ignored) {
                    // Cancelled on unload; nothing to update.
                } catch (Exception ex) {
                    fail("Failed to preview against instance", ex);
                } finally {
                    finishBusy();
                }
            }
        });
    }

    // ---- submit ----

    private void onSubmit() {
        AppItem app = header.selectedApp();
        InstanceItem inst = header.selectedInstance();
        TestSetSubmissionValidator.Result validation = TestSetSubmissionValidator.validate(
                app, inst, activeSet().size(), authCombo.getSelectedIndex(),
                (AuthItem) authCombo.getSelectedItem());
        if (!validation.allowed()) {
            setStatus(validation.message());
            return;
        }
        final String authId = validation.authId();
        final String authLabel = validation.authLabel();

        stopEditing();
        activeSet().reindex();
        persistTestSets();
        jumpToFindingsButton.setEnabled(false);
        setStatus("Checking existing endpoints before submit...");
        startBusy(submitButton, "Submitting...");
        final String appId = app.applicationId;
        final String instId = inst.instanceId;
        final String appLabel = String.valueOf(app);
        final String instLabel = String.valueOf(inst);

        runTracked(new SwingWorker<SubmitResult, Void>() {
            private int newCount = 0;
            private int scanCount = 0;

            @Override
            protected SubmitResult doInBackground() throws Exception {
                List<EndpointItem> existing = client.listEndpoints(appId, instId);
                Set<String> existingIds = new HashSet<>();
                for (EndpointItem e : existing) {
                    if (e != null && e.id != null) {
                        existingIds.add(e.id);
                    }
                }
                List<StagedRequest> staged = activeSet().items();
                List<NewEndpoint> toAdd = new ArrayList<>();
                List<String> scanIds = new ArrayList<>();
                List<String> addLines = new ArrayList<>();
                List<String> scanLines = new ArrayList<>();
                int concrete = 0;
                for (StagedRequest req : staged) {
                    String eid = req.endpointId();
                    scanIds.add(eid);
                    scanLines.add(req.getMethod().toUpperCase() + " " + req.getPath());
                    if (PathTemplatizer.hasConcreteValues(req.getPath())) {
                        concrete++;
                    }
                    if (!existingIds.contains(eid)) {
                        // add-endpoints uses the LOWERCASE method; scan uses the eid.
                        toAdd.add(new NewEndpoint(req.getMethod().toLowerCase(),
                                req.getPath(), req.getBody()));
                        addLines.add(req.getMethod().toUpperCase() + " " + req.getPath());
                    }
                }
                newCount = toAdd.size();
                scanCount = scanIds.size();
                final int concreteCount = concrete;

                final boolean[] proceed = {false};
                SwingUtilities.invokeAndWait(() -> proceed[0] = confirm(
                        appLabel, instLabel, authLabel, addLines, scanLines, concreteCount));
                if (!proceed[0]) {
                    return SubmitResult.cancelled();
                }

                // Mint the write capability only here, after explicit confirmation.
                ApisecClient.WriteAuthorization writeAuth = client.authorizeWrite();
                String scanId;
                if (!toAdd.isEmpty()) {
                    client.addEndpoints(appId, instId, toAdd, writeAuth);
                }
                scanId = client.initiateScan(appId, instId, scanIds, authId, writeAuth);
                if (scanId == null || scanId.isBlank()) {
                    return SubmitResult.submitted(scanId, null);
                }
                setStatus("Submitted. scanId " + scanId + ". Polling GET scans/{scanId} until Complete...");
                ScanStatus finalStatus = scanPoller.pollUntilComplete(
                        () -> client.getScan(appId, instId, scanId));
                return SubmitResult.submitted(scanId, finalStatus);
            }

            @Override
            protected void done() {
                try {
                    SubmitResult result = get();
                    if (result.cancelled) {
                        setStatus("Submit cancelled.");
                    } else if (result.finalStatus != null && result.finalStatus.isComplete()) {
                        jumpToFindingsButton.setEnabled(true);
                        setStatus("Scan Complete. scanId " + result.scanId + ". Jump to Findings when ready.");
                    } else {
                        setStatus("Submitted: added " + newCount + " new endpoint(s), scanning "
                                + scanCount + ". scanId " + result.scanId + ". Polling stopped before Complete"
                                + statusReason(result.finalStatus) + ".");
                    }
                } catch (java.util.concurrent.CancellationException ignored) {
                    // Cancelled on unload; nothing to update.
                } catch (Exception ex) {
                    fail("Submit failed", ex);
                } finally {
                    finishBusy();
                }
            }
        });
    }

    private boolean confirm(String appLabel, String instLabel, String authLabel,
                            List<String> addLines, List<String> scanLines, int concreteCount) {
        StringBuilder msg = new StringBuilder();
        msg.append("Submit to APIsec. This mutates the project and starts a scan.\n\n")
                .append("Application: ").append(appLabel).append("\n")
                .append("Instance:    ").append(instLabel).append("\n")
                .append("Auth:        ").append(authLabel).append("\n\n");
        if (concreteCount > 0) {
            // A10: warn before literal values pollute the project.
            msg.append("WARNING: ").append(concreteCount)
                    .append(" row(s) contain concrete values (e.g. /orders/123 or ?id=5).\n")
                    .append("Cancel and use 'Templatize selected' to parameterize them first,\n")
                    .append("or proceed to add them as literal endpoints.\n\n");
        }
        msg.append("New endpoints to add (").append(addLines.size()).append("):\n")
                .append(formatLines(addLines))
                .append("\nEndpoints to scan (").append(scanLines.size()).append("):\n")
                .append(formatLines(scanLines))
                .append("\nProceed?");
        int choice = JOptionPane.showConfirmDialog(dialogParent(), msg.toString(), "Confirm APIsec submit + scan",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        return choice == JOptionPane.OK_OPTION;
    }

    /** A11: list endpoints, capped with "+N more" so a long set stays readable. */
    private static String formatLines(List<String> lines) {
        if (lines.isEmpty()) {
            return "  (none)\n";
        }
        int cap = 10;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.size() && i < cap; i++) {
            sb.append("  ").append(lines.get(i)).append("\n");
        }
        if (lines.size() > cap) {
            sb.append("  +").append(lines.size() - cap).append(" more\n");
        }
        return sb.toString();
    }

    /** A12: simple count-aware phrasing, e.g. "adds 1 new endpoint" vs "adds 2 new endpoints". */
    private static String plural(int n, String singular, String plural) {
        return String.format(n == 1 ? singular : plural, n);
    }

    // ---- table ops ----

    private TestSet activeSet() {
        return testSets.activeSet();
    }

    private void onSetSelected() {
        int index = setCombo.getSelectedIndex();
        if (index < 0) {
            return;
        }
        stopEditing();
        testSets.setActiveIndex(index);
        persistActiveIndex();
        tableModel.clearLabels();
        tableModel.fireTableDataChanged();
        refreshStagedCount();
        setStatus("Active test set: " + activeSet().getName() + ". Total: " + activeSet().size() + ".");
        updateActionState();
    }

    private void onRenameSet() {
        TestSet active = activeSet();
        String name = JOptionPane.showInputDialog(dialogParent(), "Test set name", active.getName());
        if (name == null) {
            return;
        }
        try {
            active.setName(name);
            persistTestSets();
            setCombo.repaint();
            setStatus("Renamed active test set to " + active.getName() + ".");
        } catch (IllegalArgumentException ex) {
            setStatus(ex.getMessage());
        }
    }

    void renameActiveSetForTest(String name) {
        activeSet().setName(name);
        persistTestSets();
        setCombo.repaint();
    }

    private void onRemoveSelected() {
        stopEditing();
        int[] viewRows = table.getSelectedRows();
        List<StagedRequest> toRemove = new ArrayList<>();
        for (int vr : viewRows) {
            StagedRequest req = tableModel.rowAt(table.convertRowIndexToModel(vr));
            if (req != null) {
                toRemove.add(req);
            }
        }
        for (StagedRequest req : toRemove) {
            activeSet().remove(req);
        }
        persistTestSets();
        tableModel.fireTableDataChanged();
        refreshStagedCount();
        setStatus("Removed " + toRemove.size() + " from " + activeSet().getName()
                + ". Total: " + activeSet().size() + ".");
    }

    private void onClear() {
        stopEditing();
        activeSet().clear();
        persistTestSets();
        tableModel.clearLabels();
        tableModel.fireTableDataChanged();
        refreshStagedCount();
        setStatus("Cleared " + activeSet().getName() + ".");
    }

    /** A10: templatize concrete values in the selected rows' paths. */
    private void onTemplatizeSelected() {
        stopEditing();
        int[] viewRows = table.getSelectedRows();
        if (viewRows.length == 0) {
            setStatus("Select one or more rows to templatize.");
            return;
        }
        int changed = 0;
        for (int vr : viewRows) {
            StagedRequest req = tableModel.rowAt(table.convertRowIndexToModel(vr));
            if (req == null) {
                continue;
            }
            String original = req.getPath();
            String templated = PathTemplatizer.templatize(original);
            if (!templated.equals(original)) {
                req.setPath(templated);
                tableModel.clearLabelFor(req);
                changed++;
            }
        }
        if (changed > 0) {
            activeSet().reindex();
            persistTestSets();
            tableModel.fireTableDataChanged();
            setStatus("Templatized " + changed + " row(s). Review the paths, then Preview or Submit.");
        } else {
            setStatus("No concrete values found in the selected row(s).");
        }
    }

    /** A7: right-click menu on the staged table + double-click to view full body. */
    private void installTablePopup() {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem editPath = new JMenuItem("Edit path");
        editPath.addActionListener(e -> onEditPathSelected());
        JMenuItem templatize = new JMenuItem("Templatize selected");
        templatize.addActionListener(e -> onTemplatizeSelected());
        JMenuItem viewBody = new JMenuItem("View body");
        viewBody.addActionListener(e -> onShowBody());
        JMenuItem remove = new JMenuItem("Remove selected");
        remove.addActionListener(e -> onRemoveSelected());
        menu.add(editPath);
        menu.add(templatize);
        menu.add(viewBody);
        menu.addSeparator();
        menu.add(remove);

        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                maybePopup(e);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                maybePopup(e);
            }

            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                // Double-click the Body column to view full content.
                if (e.getClickCount() == 2) {
                    int viewRow = table.rowAtPoint(e.getPoint());
                    int viewCol = table.columnAtPoint(e.getPoint());
                    if (viewRow >= 0 && table.convertColumnIndexToModel(viewCol) == 2) {
                        onShowBody();
                    }
                }
            }

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

    private void onEditPathSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            setStatus("Select a row to edit its path.");
            return;
        }
        StagedRequest req = tableModel.rowAt(table.convertRowIndexToModel(viewRow));
        if (req == null) {
            return;
        }
        String edited = JOptionPane.showInputDialog(dialogParent(), "Path (templatize values like /{order_id})", req.getPath());
        if (edited == null) {
            return;
        }
        req.setPath(edited);
        activeSet().reindex();
        persistTestSets();
        tableModel.clearLabelFor(req);
        tableModel.fireTableDataChanged();
        setStatus("Edited path. Review, then Preview or Submit.");
    }

    private void onShowBody() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            setStatus("Select a row to view its body.");
            return;
        }
        StagedRequest req = tableModel.rowAt(table.convertRowIndexToModel(viewRow));
        if (req == null) {
            return;
        }
        String body = req.getBody();
        if (body == null || body.isEmpty()) {
            JOptionPane.showMessageDialog(dialogParent(), "No body captured for this staged request.",
                    req.getMethod() + " " + req.getPath() + " body", JOptionPane.INFORMATION_MESSAGE);
            setStatus("This staged request has no body.");
            return;
        }
        JTextArea area = new JTextArea(body, 20, 60);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        JOptionPane.showMessageDialog(dialogParent(), new JScrollPane(area),
                req.getMethod() + " " + req.getPath() + " body", JOptionPane.PLAIN_MESSAGE);
    }

    private Component dialogParent() {
        if (api != null) {
            try {
                return api.userInterface().swingUtils().suiteFrame();
            } catch (RuntimeException ignored) {
                return this;
            }
        }
        return this;
    }

    private void stopEditing() {
        if (table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }
    }

    private void updateActionState() {
        Runnable update = () -> {
            boolean headerBusy = header != null && header.isBusy();
            boolean canAct = !busy && !headerBusy;
            setCombo.setEnabled(canAct);
            renameSetButton.setEnabled(canAct);
            loadAuthsButton.setEnabled(canAct);
            removeButton.setEnabled(canAct);
            clearButton.setEnabled(canAct);
            templatizeButton.setEnabled(canAct);
            previewButton.setEnabled(canAct);
            submitButton.setEnabled(canAct);
            // Cancel is the one control that stays live while this panel is busy.
            cancelButton.setEnabled(busy);
            if (busy || headerBusy) {
                jumpToFindingsButton.setEnabled(false);
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            update.run();
        } else {
            SwingUtilities.invokeLater(update);
        }
    }

    /** Runs a worker under the shared unload-cancel tracker and remembers it so Cancel can stop it. */
    private void runTracked(SwingWorker<?, ?> worker) {
        activeWorker = worker;
        tasks.execute(worker);
    }

    private void onCancel() {
        SwingWorker<?, ?> worker = activeWorker;
        if (worker != null && !worker.isDone()) {
            worker.cancel(true);
            setStatus("Cancelling...");
        }
    }

    private void startBusy(JButton button, String loadingText) {
        busy = true;
        busyButton = button;
        if (button != null) {
            if (button.getClientProperty("relay.defaultText") == null) {
                button.putClientProperty("relay.defaultText", button.getText());
            }
            button.setText(loadingText);
        }
        updateActionState();
    }

    private void finishBusy() {
        activeWorker = null;
        JButton button = busyButton;
        busyButton = null;
        if (button != null) {
            Object defaultText = button.getClientProperty("relay.defaultText");
            if (defaultText instanceof String) {
                button.setText((String) defaultText);
            }
            button.putClientProperty("relay.defaultText", null);
        }
        busy = false;
        updateActionState();
    }

    private void persistActiveIndex() {
        if (state != null) {
            state.saveActiveTestSetIndex(testSets.activeIndex());
        }
    }

    private void persistTestSets() {
        if (state != null) {
            state.saveActiveTestSetIndex(testSets.activeIndex());
            state.saveTestSets(testSets);
        }
    }

    private void saveAuthSelection() {
        if (state == null || populatingAuths) {
            return;
        }
        AuthItem auth = (AuthItem) authCombo.getSelectedItem();
        if (auth == null) {
            state.saveAuthSelection(null);
        } else if (auth == NO_AUTH || auth.authId == null || auth.authId.isBlank()) {
            state.saveAuthSelection(RelayProjectState.NO_AUTH_SELECTION);
        } else {
            state.saveAuthSelection(auth.authId);
        }
    }

    private void restoreAuthSelection() {
        populatingAuths = true;
        try {
            String saved = state == null ? null : state.lastAuthId();
            if (RelayProjectState.NO_AUTH_SELECTION.equals(saved)) {
                authCombo.setSelectedItem(NO_AUTH);
                return;
            }
            if (saved != null) {
                for (int i = 0; i < authCombo.getItemCount(); i++) {
                    AuthItem item = authCombo.getItemAt(i);
                    if (item != null && saved.equals(item.authId)) {
                        authCombo.setSelectedIndex(i);
                        return;
                    }
                }
            }
            authCombo.setSelectedIndex(-1);
        } finally {
            populatingAuths = false;
        }
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

    private static String statusReason(ScanStatus status) {
        if (status == null) {
            return "";
        }
        String state = status.status == null || status.status.isBlank() ? "unknown" : status.status.trim();
        String reason = status.statusReason == null || status.statusReason.isBlank()
                ? "" : ": " + status.statusReason.trim();
        return " with status " + state + reason;
    }

    private static final class SubmitResult {
        final boolean cancelled;
        final String scanId;
        final ScanStatus finalStatus;

        private SubmitResult(boolean cancelled, String scanId, ScanStatus finalStatus) {
            this.cancelled = cancelled;
            this.scanId = scanId == null || scanId.isBlank() ? "(none)" : scanId;
            this.finalStatus = finalStatus;
        }

        static SubmitResult cancelled() {
            return new SubmitResult(true, null, null);
        }

        static SubmitResult submitted(String scanId, ScanStatus finalStatus) {
            return new SubmitResult(false, scanId, finalStatus);
        }
    }

    private static AuthItem noAuthSentinel() {
        AuthItem a = new AuthItem();
        a.authId = null;
        a.name = "No auth";
        return a;
    }

    /** Table: Method (ro), Path (editable), Body (ro, truncated), Origin (ro), Status (ro). */
    private final class StagedTableModel extends AbstractTableModel {
        private final String[] cols = {"Method", "Path", "Body", "Origin", "Status"};
        private final java.util.Map<StagedRequest, String> labels = new java.util.HashMap<>();

        void setLabel(StagedRequest req, String label) {
            labels.put(req, label);
        }

        void clearLabels() {
            labels.clear();
        }

        void clearLabelFor(StagedRequest req) {
            labels.remove(req);
        }

        StagedRequest rowAt(int i) {
            List<StagedRequest> rows = activeSet().items();
            return (i >= 0 && i < rows.size()) ? rows.get(i) : null;
        }

        @Override
        public int getRowCount() {
            return activeSet().size();
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
        public boolean isCellEditable(int r, int c) {
            return c == 1; // Path only
        }

        @Override
        public Object getValueAt(int r, int c) {
            StagedRequest req = rowAt(r);
            if (req == null) {
                return "";
            }
            switch (c) {
                case 0: return req.getMethod();
                case 1: return req.getPath();
                case 2: return truncate(req.getBody());
                case 3: return req.getOrigin();
                case 4: {
                    String label = labels.get(req);
                    if (label != null) {
                        return label;
                    }
                    // A10: flag rows that still carry concrete values pre-preview.
                    return PathTemplatizer.hasConcreteValues(req.getPath()) ? "concrete?" : "";
                }
                default: return "";
            }
        }

        @Override
        public void setValueAt(Object value, int r, int c) {
            if (c != 1) {
                return;
            }
            StagedRequest req = rowAt(r);
            if (req != null) {
                req.setPath(value == null ? "" : value.toString());
                persistTestSets();
                // Editing a path can change NEW/PRESENT; clear the stale label.
                labels.remove(req);
                fireTableRowsUpdated(r, r);
            }
        }

        private String truncate(String body) {
            if (body == null || body.isEmpty()) {
                return "";
            }
            String oneLine = body.replaceAll("[\\r\\n\\t]+", " ");
            return oneLine.length() > 80 ? oneLine.substring(0, 80) + "..." : oneLine;
        }
    }

    /** Shows a placeholder when nothing is selected, and a tooltip with the full value (D4). */
    private static final class TooltipRenderer extends DefaultListCellRenderer {
        private final String placeholder;

        TooltipRenderer(String placeholder) {
            this.placeholder = placeholder;
        }

        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            Object shown = value == null ? placeholder : value;
            Component c = super.getListCellRendererComponent(list, shown, index, isSelected, cellHasFocus);
            if (value != null && list != null) {
                list.setToolTipText(String.valueOf(value));
            }
            if (c instanceof JComponent) {
                ((JComponent) c).setToolTipText(value == null ? null : String.valueOf(value));
                HtmlSafe.harden((JComponent) c);
            }
            return c;
        }
    }
}
