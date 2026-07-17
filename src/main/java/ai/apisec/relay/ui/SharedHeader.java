package ai.apisec.relay.ui;

import ai.apisec.relay.apisec.ApisecClient;
import ai.apisec.relay.apisec.model.ApplicationModels.AppDetail;
import ai.apisec.relay.apisec.model.ApplicationModels.AppItem;
import ai.apisec.relay.apisec.model.ApplicationModels.InstanceItem;
import ai.apisec.relay.burp.BackgroundTasks;
import ai.apisec.relay.config.RelayConfig;
import ai.apisec.relay.config.RelayProjectState;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Shared header above both sub-tabs (A1 + R4).
 *
 * Owns host/PAT config and the single Application + Instance selection that both
 * the Findings and Test set tabs read, so the operator selects once and the two
 * tabs cannot drift apart. Applications load automatically on initialize, so
 * neither tab needs a manual refresh. Scan auth stays on the Test set tab because
 * it is write-only.
 */
public final class SharedHeader extends JPanel {

    private final MontoyaApi api;
    private final RelayConfig config;
    private final ApisecClient client;
    private final RelayProjectState state;
    private final BackgroundTasks tasks;

    private final JTextField hostField = new JTextField(30);
    private final JPasswordField patField = new JPasswordField(30);
    private final JButton saveButton = new JButton("Save");
    private final JButton clearPatButton = new JButton("Clear PAT");
    private final JButton refreshButton = new JButton("Refresh applications");
    private final JComboBox<AppItem> appCombo = new JComboBox<>();
    private final JComboBox<InstanceItem> instanceCombo = new JComboBox<>();
    private final JLabel status = new JLabel(" ");

    private boolean populating = false;
    private boolean busy = false;

    // Listeners notified when the selected instance changes (incl. cleared).
    private final List<Runnable> instanceListeners = new ArrayList<>();
    // Listeners notified when busy state flips, so tabs can disable their controls.
    private final List<Consumer<Boolean>> busyListeners = new ArrayList<>();

    public SharedHeader(MontoyaApi api, RelayConfig config, ApisecClient client) {
        this(api, config, client, null, new BackgroundTasks());
    }

    public SharedHeader(MontoyaApi api, RelayConfig config, ApisecClient client,
                        RelayProjectState state) {
        this(api, config, client, state, new BackgroundTasks());
    }

    public SharedHeader(MontoyaApi api, RelayConfig config, ApisecClient client,
                        RelayProjectState state, BackgroundTasks tasks) {
        this.api = api;
        this.config = config;
        this.client = client;
        this.state = state;
        this.tasks = tasks == null ? new BackgroundTasks() : tasks;

        setLayout(new BorderLayout(8, 4));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
        add(buildConfigRow(), BorderLayout.NORTH);
        add(buildTargetRow(), BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);

        HtmlSafe.harden(status);
        hostField.setText(config.host());
        patField.setText(config.pat());
        wire();
    }

    private JComponent buildConfigRow() {
        saveButton.addActionListener(e -> onSave());
        clearPatButton.addActionListener(e -> onClearPat());
        return buildConfigRow(hostField, patField, saveButton, clearPatButton);
    }

    static JPanel buildConfigRowForTest() {
        return buildConfigRow(new JTextField(30), new JPasswordField(30),
                new JButton("Save"), new JButton("Clear PAT"));
    }

    private static JPanel buildConfigRow(JTextField hostField, JPasswordField patField,
                                         JButton saveButton, JButton clearPatButton) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        p.add(new JLabel("APIsec host"));
        p.add(hostField);
        p.add(patLabel());
        p.add(patField);
        p.add(saveButton);
        p.add(clearPatButton);

        JTextArea cue = new JTextArea(relayIntroText());
        cue.setEditable(false);
        cue.setFocusable(false);
        cue.setRows(3);
        cue.setLineWrap(false);
        cue.setWrapStyleWord(true);
        cue.setOpaque(false);

        cue.setFont(UIManager.getFont("Label.font"));
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.add(p, BorderLayout.NORTH);
        wrap.add(cue, BorderLayout.CENTER);
        return wrap;
    }

    static JLabel patLabel() {
        JLabel label = new JLabel("PAT");
        label.setToolTipText("Saved in Burp preferences. Clear PAT deletes it. Write scope needed for Test set scans.");
        return label;
    }

    static String relayIntroText() {
        return "Move findings from APIsec.ai to Burp for hands-on testing.\n"
                + "Send curated requests back to APIsec for focused scans.\n"
                + "Burp handles the attack work. APIsec keeps testing continuous.";
    }

    private JComponent buildTargetRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        refreshButton.addActionListener(e -> loadApplications());
        p.add(refreshButton);
        p.add(new JLabel("Application"));
        appCombo.setRenderer(new PlaceholderRenderer("Select an application"));
        p.add(appCombo);
        p.add(new JLabel("Instance"));
        instanceCombo.setRenderer(new PlaceholderRenderer("Select an instance"));
        p.add(instanceCombo);
        return p;
    }

    private void wire() {
        appCombo.addActionListener(e -> {
            if (populating) {
                return;
            }
            AppItem app = (AppItem) appCombo.getSelectedItem();
            if (app != null) {
                saveTargetSelection(app.applicationId, null);
                loadInstances(app);
            }
        });
        instanceCombo.addActionListener(e -> {
            if (!populating) {
                saveCurrentSelection();
                fireInstanceChanged();
            }
        });
    }

    /** Auto-load applications once the tab is registered. Call from initialize(). */
    public void autoLoad() {
        if (config.pat() == null || config.pat().isBlank()) {
            setStatus("Set host and PAT, then Save. Applications load automatically once a PAT is present.");
            return;
        }
        loadApplications();
    }

    // ---- selection accessors used by both tabs ----

    public AppItem selectedApp() {
        return (AppItem) appCombo.getSelectedItem();
    }

    public InstanceItem selectedInstance() {
        return (InstanceItem) instanceCombo.getSelectedItem();
    }

    public void addInstanceChangeListener(Runnable r) {
        instanceListeners.add(r);
    }

    public void addBusyListener(Consumer<Boolean> l) {
        busyListeners.add(l);
    }

    public boolean isBusy() {
        return busy;
    }

    public void setStatus(String text) {
        if (SwingUtilities.isEventDispatchThread()) {
            status.setText(text);
        } else {
            SwingUtilities.invokeLater(() -> status.setText(text));
        }
    }

    private void fireInstanceChanged() {
        for (Runnable r : instanceListeners) {
            r.run();
        }
    }

    private void setBusy(boolean b) {
        busy = b;
        refreshButton.setEnabled(!b);
        saveButton.setEnabled(!b);
        appCombo.setEnabled(!b);
        instanceCombo.setEnabled(!b);
        for (Consumer<Boolean> l : busyListeners) {
            l.accept(b);
        }
    }

    // ---- config actions ----

    private void onSave() {
        if (!saveConfig()) {
            return;
        }
        setStatus("Saved. Loading applications...");
        loadApplications();
    }

    /**
     * Persists host + PAT after validation. The host must be a well-formed
     * https:// URL so the PAT is never sent in cleartext; a rejected value
     * surfaces in the status line and aborts the caller.
     */
    private boolean saveConfig() {
        try {
            config.save(hostField.getText(), new String(patField.getPassword()));
        } catch (IllegalArgumentException ex) {
            setStatus(ex.getMessage());
            return false;
        }
        hostField.setText(config.host());
        client.configure(config.host(), config.pat());
        return true;
    }

    private void onClearPat() {
        config.clearPat();
        patField.setText("");
        client.configure(config.host(), "");
        setStatus("PAT cleared.");
    }

    // ---- loading ----

    private void loadApplications() {
        if (!saveConfig()) {
            return;
        }
        setStatus("Loading applications...");
        setButtonLoading(refreshButton, true, "Refreshing...");
        setBusy(true);
        tasks.execute(new SwingWorker<List<AppItem>, Void>() {
            @Override
            protected List<AppItem> doInBackground() throws Exception {
                return client.listApplications();
            }

            @Override
            protected void done() {
                try {
                    List<AppItem> apps = get();
                    populating = true;
                    appCombo.removeAllItems();
                    instanceCombo.removeAllItems();
                    for (AppItem a : apps) {
                        appCombo.addItem(a);
                    }
                    populating = false;
                    int restore = indexOfApp(apps, state == null ? null : state.lastAppId());
                    if (restore >= 0) {
                        appCombo.setSelectedIndex(restore);
                        setStatus("Loaded " + apps.size() + " applications. Restored last application.");
                    } else {
                        appCombo.setSelectedIndex(-1);
                        saveTargetSelection(null, null);
                        fireInstanceChanged();
                        setStatus("Loaded " + apps.size() + " applications. Select one.");
                    }
                } catch (java.util.concurrent.CancellationException ignored) {
                    populating = false;
                } catch (Exception ex) {
                    populating = false;
                    fail("Failed to load applications", ex);
                } finally {
                    setButtonLoading(refreshButton, false, null);
                    setBusy(false);
                }
            }
        });
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

    private void loadInstances(AppItem app) {
        setStatus("Loading instances...");
        setBusy(true);
        tasks.execute(new SwingWorker<AppDetail, Void>() {
            @Override
            protected AppDetail doInBackground() throws Exception {
                return client.getApplication(app.applicationId);
            }

            @Override
            protected void done() {
                try {
                    AppDetail detail = get();
                    populating = true;
                    instanceCombo.removeAllItems();
                    int n = 0;
                    if (detail != null && detail.instances != null) {
                        for (InstanceItem i : detail.instances) {
                            instanceCombo.addItem(i);
                            n++;
                        }
                    }
                    populating = false;
                    int restore = indexOfInstance(detail == null ? null : detail.instances,
                            state == null ? null : state.lastInstanceId());
                    if (restore >= 0) {
                        instanceCombo.setSelectedIndex(restore);
                    } else {
                        instanceCombo.setSelectedIndex(n == 1 ? 0 : -1);
                    }
                    saveCurrentSelection();
                    fireInstanceChanged();
                    setStatus("Loaded " + n + " instance(s)."
                            + (instanceCombo.getSelectedIndex() >= 0 ? "" : " Select one."));
                } catch (java.util.concurrent.CancellationException ignored) {
                    populating = false;
                } catch (Exception ex) {
                    populating = false;
                    fail("Failed to load instances", ex);
                } finally {
                    setBusy(false);
                }
            }
        });
    }

    private void fail(String prefix, Exception ex) {
        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
        api.logging().logToError(prefix + " :: " + cause.getMessage());
        setStatus(prefix + ": " + cause.getMessage());
    }

    private void saveCurrentSelection() {
        AppItem app = selectedApp();
        InstanceItem inst = selectedInstance();
        saveTargetSelection(app == null ? null : app.applicationId,
                inst == null ? null : inst.instanceId);
    }

    private void saveTargetSelection(String appId, String instanceId) {
        if (state != null) {
            state.saveTargetSelection(appId, instanceId);
        }
    }

    private static int indexOfApp(List<AppItem> apps, String appId) {
        if (apps == null || appId == null) {
            return -1;
        }
        for (int i = 0; i < apps.size(); i++) {
            AppItem app = apps.get(i);
            if (app != null && appId.equals(app.applicationId)) {
                return i;
            }
        }
        return -1;
    }

    private static int indexOfInstance(List<InstanceItem> instances, String instanceId) {
        if (instances == null || instanceId == null) {
            return -1;
        }
        for (int i = 0; i < instances.size(); i++) {
            InstanceItem inst = instances.get(i);
            if (inst != null && instanceId.equals(inst.instanceId)) {
                return i;
            }
        }
        return -1;
    }

    private static final class PlaceholderRenderer extends DefaultListCellRenderer {
        private final String placeholder;

        PlaceholderRenderer(String placeholder) {
            this.placeholder = placeholder;
        }

        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            Object shown = value == null ? placeholder : value;
            Component c = super.getListCellRendererComponent(list, shown, index, isSelected, cellHasFocus);
            if (c instanceof JComponent) {
                HtmlSafe.harden((JComponent) c);
            }
            return c;
        }
    }
}
