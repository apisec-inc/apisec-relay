package ai.apisec.relay.ui;

import ai.apisec.relay.testset.TestSet.StagedRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class TestSetContextMenuTest {

    @Test
    void stagedRequestKeepsFullPathWithQueryString() {
        HttpRequest request = request("GET", "/api/orders", "id=123&expand=true", "/api/orders", "");
        HttpRequestResponse rr = requestResponse(request);

        List<StagedRequest> staged = TestSetContextMenu.toStagedRequests(List.of(rr));

        assertEquals(1, staged.size());
        assertEquals("GET", staged.get(0).getMethod());
        assertEquals("/api/orders?id=123&expand=true", staged.get(0).getPath());
    }

    @Test
    void stagedRequestCanCarryTemplatizedQueryParamsFromEditablePathCell() {
        HttpRequest request = request("GET", "/api/orders", "id=123&expand=true", "/api/orders", "");
        StagedRequest staged = TestSetContextMenu.toStagedRequests(List.of(requestResponse(request))).get(0);

        staged.setPath("/api/orders?id={order_id}&expand={expand_flag}");

        assertEquals("/api/orders?id={order_id}&expand={expand_flag}", staged.getPath());
    }

    private static HttpRequestResponse requestResponse(HttpRequest request) {
        return (HttpRequestResponse) Proxy.newProxyInstance(
                HttpRequestResponse.class.getClassLoader(),
                new Class<?>[]{HttpRequestResponse.class},
                (proxy, method, args) -> {
                    if ("request".equals(method.getName())) {
                        return request;
                    }
                    if ("url".equals(method.getName())) {
                        return "https://example.test" + request.path();
                    }
                    if (method.getReturnType().equals(boolean.class)) {
                        return false;
                    }
                    if (method.getReturnType().equals(short.class)) {
                        return (short) 0;
                    }
                    return null;
                });
    }

    private static HttpRequest request(String methodValue, String path, String query, String pathWithoutQuery, String body) {
        return (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "method" -> methodValue;
                    case "path" -> path;
                    case "query" -> query;
                    case "pathWithoutQuery" -> pathWithoutQuery;
                    case "bodyToString" -> body;
                    case "url" -> "https://example.test" + path;
                    default -> defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (type.equals(boolean.class)) {
            return false;
        }
        if (type.equals(short.class)) {
            return (short) 0;
        }
        if (type.equals(int.class)) {
            return 0;
        }
        return null;
    }
}
