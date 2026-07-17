# APIsec Relay

APIsec Relay is a Burp Suite extension that connects Burp Suite with [APIsec.ai](https://www.apisec.ai) in both directions:

- **Findings tab (read):** pull APIsec findings into Burp and replay each finding's proof-of-concept request chain into Repeater for hands-on testing.
- **Test Sets tab (write):** stage requests discovered in Burp, deduplicate them against an APIsec instance, add the new endpoints, and start a focused APIsec scan after explicit confirmation.

## Requirements

- Burp Suite (Professional or Community) with Montoya API support
- Java 17+ (to build from source)
- An APIsec.ai tenant and a Personal Access Token (PAT)
  - Findings (read path) works with a read-scoped PAT.
  - Test Set submission (write path) requires a write-scoped PAT; APIsec rejects writes from read-only tokens.

## Installation

Build the shaded jar:

```bash
./gradlew clean test shadowJar --no-daemon
```

Then in Burp: **Extensions → Installed → Add → Extension type: Java** and select:

```text
build/libs/apisec-relay-1.0.0-all.jar
```

## Setup

1. Open the **APIsec Relay** tab.
2. Enter your APIsec host (defaults to `https://api.apisecapps.com`) and PAT, then click **Save**. The host must be an `https://` URL. Plain `http://` is rejected so the PAT is never sent in cleartext, and a scheme-less value is treated as `https://`.
3. Applications load automatically. Pick an **Application** and **Instance** in the shared header; both sub-tabs use that selection.

The PAT is stored in Burp's cross-project preferences (unencrypted, like other Burp preferences) so it survives restarts. **Clear PAT** deletes it.

## Usage

### Findings (read)

1. Click **Load findings** to fetch the instance's detections.
2. Filter by severity, status, or free text; columns sort (severity sorts by CVSS score).
3. Select one or more findings and click **Send to Repeater**. Each finding's captured request chain arrives as Repeater tabs named `METHOD /resource [auth|no-auth]`; untick *Also send unauthenticated request* to skip the no-auth control request.
4. Right-click a finding to send it to Repeater or stage its endpoint into the active test set.

### Test Sets (write)

1. Right-click requests anywhere in Burp (Proxy history, site map, Repeater) and choose **APIsec Relay: Add to test set**. Staged requests are deduplicated by method + path.
2. Optionally **Template paths** to convert concrete values (`/orders/123`, `?id=5`) into APIsec path templates (`/orders/{order_id}`), or edit a path inline.
3. Pick a **Scan auth** (or the explicit *No auth* entry for an unauthenticated scan).
4. **Preview NEW/PRESENT** to see which staged endpoints already exist on the instance.
5. **Submit and scan**: a confirmation dialog lists exactly which endpoints will be added and scanned. Nothing is written to APIsec until you confirm. After submission the extension polls the scan until it completes, then offers a jump to the Findings tab. Use **Cancel** to stop a running submit or scan poll at any time.

Test set contents are saved per Burp project; test set names are saved across projects.

## Network and privacy notes

- All APIsec traffic goes through Burp's Montoya HTTP API, so Burp's upstream proxy, TLS, and network settings are honored.
- When a PAT is saved, the extension contacts the configured APIsec host at load time to list your applications.
- The read path (Findings) only issues GET requests. The write path issues POSTs (add endpoints, start scan) only after the confirmation dialog; the staged request method, path, and body are sent to APIsec at that point.
- When the extension is unloaded, any in-flight background work (including a running scan poll) is cancelled.
- Error responses are sanitized before logging: Authorization headers, bearer tokens, and PAT-like values are redacted, and output is length-capped.
- APIsec Relay does not use AI providers, does not download vulnerability definitions, and sends no telemetry.

## Troubleshooting

To log (sanitized, truncated) APIsec error response bodies for debugging, set the environment variable `APISEC_RELAY_DEBUG_RESPONSES=true` or start Burp with `-Dapisec.relay.debugResponses=true`. Errors appear under **Extensions → APIsec Relay → Errors**.

## Development

```bash
./gradlew clean test shadowJar --no-daemon
```

Unit tests cover the API client, models, endpoint-ID rules, path templatizing, and UI behavior; CI runs the same build on every push.

## License

Licensed under the [Apache License 2.0](LICENSE).
