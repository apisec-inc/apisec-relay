package ai.apisec.relay.ui;

import ai.apisec.relay.testset.TestSet.StagedRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Adds "APIsec Relay: Add to test set" to Burp's Extensions context submenu.
 *
 * Works for both a single request in an editor (Repeater, proxy intercept) and a
 * multi-selection in the site map or proxy history. The two sources are unioned
 * so the same provider handles individual-request and group selection.
 *
 * Each request is reduced to method + path (with query) + body and handed to
 * the panel's staging callback, which dedups and refreshes the table on the EDT.
 */
public final class TestSetContextMenu implements ContextMenuItemsProvider {

    private final Consumer<List<StagedRequest>> onStage;

    public TestSetContextMenu(Consumer<List<StagedRequest>> onStage) {
        this.onStage = onStage;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event == null) {
            return List.of();
        }
        List<HttpRequestResponse> selected = collect(event);
        if (selected.isEmpty()) {
            return List.of();
        }
        JMenuItem item = new JMenuItem("APIsec Relay: Add to test set");
        item.addActionListener(e -> {
            List<StagedRequest> staged = toStagedRequests(selected);
            if (!staged.isEmpty()) {
                onStage.accept(staged);
            }
        });
        return List.of(item);
    }

    /** Union of editor request and multi-selection, deduped by identity. */
    private static List<HttpRequestResponse> collect(ContextMenuEvent event) {
        // LinkedHashMap on identity-ish key (method+url) keeps order, drops dupes.
        Map<String, HttpRequestResponse> union = new LinkedHashMap<>();
        event.messageEditorRequestResponse().ifPresent(editor -> {
            HttpRequestResponse rr = editor.requestResponse();
            if (rr != null && rr.request() != null) {
                union.put(identity(rr.request()), rr);
            }
        });
        for (HttpRequestResponse rr : event.selectedRequestResponses()) {
            if (rr != null && rr.request() != null) {
                union.putIfAbsent(identity(rr.request()), rr);
            }
        }
        return new ArrayList<>(union.values());
    }

    private static String identity(HttpRequest req) {
        String method = req.method() == null ? "" : req.method();
        String url;
        try {
            url = req.url();
        } catch (RuntimeException ex) {
            // url() can throw if the request has no service; fall back to path.
            url = req.pathWithoutQuery();
        }
        return method + " " + url;
    }

    static List<StagedRequest> toStagedRequests(List<HttpRequestResponse> selected) {
        List<StagedRequest> out = new ArrayList<>();
        for (HttpRequestResponse rr : selected) {
            HttpRequest req = rr.request();
            if (req == null) {
                continue;
            }
            String method = req.method() == null ? "" : req.method();
            // R3: keep the query string so parameters reach the staged set. Some
            // Montoya request sources expose path() without query, so stitch it
            // back from query() instead of relying on path() alone.
            String path = fullPathWithQuery(req);
            String body = req.bodyToString() == null ? "" : req.bodyToString();
            if (path.isBlank()) {
                continue;
            }
            out.add(new StagedRequest(method, path, body, "burp"));
        }
        return out;
    }

    static String fullPathWithQuery(HttpRequest req) {
        if (req == null) {
            return "";
        }
        String path = req.path() == null ? "" : req.path();
        if (path.contains("?")) {
            return path;
        }
        String query = req.query() == null ? "" : req.query();
        if (query.isBlank()) {
            return path;
        }
        return path + "?" + query;
    }
}
