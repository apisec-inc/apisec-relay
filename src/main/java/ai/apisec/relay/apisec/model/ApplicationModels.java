package ai.apisec.relay.apisec.model;

import java.util.List;

/**
 * Maps GET /v1/applications and GET /v1/applications/{id}.
 * Unknown JSON fields are ignored by Gson, so these stay minimal.
 */
public final class ApplicationModels {

    public static final class AppsResponse {
        public List<AppItem> applications;
        public String nextToken;
    }

    public static final class AppItem {
        public String applicationId;
        public String applicationName;
        public String applicationType;

        @Override
        public String toString() {
            String name = applicationName == null ? "(unnamed)" : applicationName;
            String type = applicationType == null ? "" : "  [" + applicationType + "]";
            return name + type;
        }
    }

    public static final class AppDetail {
        public String applicationId;
        public String applicationName;
        public List<InstanceItem> instances;
    }

    public static final class InstanceItem {
        public String instanceId;
        public String hostUrl;

        @Override
        public String toString() {
            String url = hostUrl == null ? "(no host)" : hostUrl;
            return url + "  " + shortId(instanceId);
        }

        private static String shortId(String id) {
            if (id == null) return "";
            return id.length() <= 8 ? id : id.substring(0, 8);
        }
    }

    private ApplicationModels() {
    }
}
