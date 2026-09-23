# Grafana Log Filtering Implementation Plan
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make OpenPPP2 logs easy to filter in both Grafana Explore and the provisioned log dashboard without introducing high-cardinality Loki labels.

**Architecture:** Normalize selected OTLP log fields in the OpenTelemetry Collector, use `groupbyattrs` to promote them to resource attributes, and let Loki 3.3.2 index only an explicit low-cardinality whitelist. Replace the existing broken dashboard in place while keeping historical logs queryable through structured-metadata pipeline filters.

**Tech Stack:** OpenTelemetry Collector Contrib 0.104.0, Loki 3.3.2 native OTLP ingestion, Grafana 11.4 provisioning, LogQL, Docker Compose.

---

### Task 1: Capture Baseline and Backups

**Files:**
- Read: `/opt/openppp2-otel/otel-collector-config.yaml`
- Read: `/opt/openppp2-otel/loki-config.yaml`
- Read: `/opt/openppp2-otel/dashboards/openppp2-logs.json`
- Create remotely: timestamped `.bak-YYYYMMDDHHMMSS` copies of those three files

- [ ] **Step 1: Record the current container and datasource health**

Run remotely:

```bash
docker compose -f /opt/openppp2-otel/docker-compose.yml ps
curl -fsS http://127.0.0.1:3100/ready
curl -fsS http://127.0.0.1:3944/api/health
```

Expected: all three observability containers are running, Loki returns `ready`, and Grafana reports database `ok`.

- [ ] **Step 2: Record current indexed labels**

Run through the Grafana datasource proxy:

```text
GET /api/datasources/proxy/uid/loki/loki/api/v1/labels
```

Expected baseline: only `service_name` and `service_namespace` are indexed for current OpenPPP2 data.

- [ ] **Step 3: Create timestamped backups**

Run remotely:

```bash
stamp=$(date -u +%Y%m%d%H%M%S)
cp -a /opt/openppp2-otel/otel-collector-config.yaml /opt/openppp2-otel/otel-collector-config.yaml.bak-$stamp
cp -a /opt/openppp2-otel/loki-config.yaml /opt/openppp2-otel/loki-config.yaml.bak-$stamp
cp -a /opt/openppp2-otel/dashboards/openppp2-logs.json /opt/openppp2-otel/dashboards/openppp2-logs.json.bak-$stamp
```

Expected: three backup files with the same timestamp.

### Task 2: Normalize and Promote Low-Cardinality OTLP Fields

**Files:**
- Modify remotely: `/opt/openppp2-otel/otel-collector-config.yaml`
- Modify remotely: `/opt/openppp2-otel/loki-config.yaml`

- [ ] **Step 1: Add Collector normalization statements**

Add these statements to `transform/format.log_statements` before formatting the body:

```yaml
- 'set(attributes["severity_text"], severity_text) where severity_text != nil and severity_text != ""'
- 'set(attributes["event_name"], attributes["event.name"]) where attributes["event.name"] != nil'
- 'set(attributes["scope_name"], instrumentation_scope.name) where instrumentation_scope.name != nil and instrumentation_scope.name != ""'
- 'set(attributes["openppp2_dataplane"], attributes["openppp2.dataplane"]) where attributes["openppp2.dataplane"] != nil'
- 'set(attributes["openppp2_packet_direction"], attributes["openppp2.packet.direction"]) where attributes["openppp2.packet.direction"] != nil'
- 'set(attributes["openppp2_link_state"], attributes["openppp2.link_state"]) where attributes["openppp2.link_state"] != nil'
```

Do not copy `machine_id`, packet number, packet summary, address, port, or counters.

- [ ] **Step 2: Add and wire the grouping processor**

Add:

```yaml
  groupbyattrs/log-index:
    keys:
      - severity_text
      - event_name
      - scope_name
      - openppp2_dataplane
      - openppp2_packet_direction
      - openppp2_link_state
```

Change the logs pipeline to:

```yaml
processors: [resource, transform/timestamp, transform/format, groupbyattrs/log-index, batch]
```

`os.type` remains an existing resource attribute and does not need grouping.

- [ ] **Step 3: Configure Loki's explicit OTLP resource label whitelist**

Extend `limits_config` with:

```yaml
  otlp_config:
    resource_attributes:
      ignore_defaults: true
      attributes_config:
        - action: index_label
          attributes:
            - service.name
            - service.namespace
            - severity_text
            - event_name
            - os.type
            - scope_name
            - openppp2_dataplane
            - openppp2_packet_direction
            - openppp2_link_state
```

Expected: at most nine selected index labels; all other attributes remain structured metadata.

- [ ] **Step 4: Validate both configurations before restart**

Run remotely:

```bash
docker run --rm -v /opt/openppp2-otel/otel-collector-config.yaml:/etc/otelcol/config.yaml:ro otel/opentelemetry-collector-contrib:0.104.0 validate --config=/etc/otelcol/config.yaml
docker run --rm -v /opt/openppp2-otel/loki-config.yaml:/etc/loki/config.yaml:ro grafana/loki:3.3.2 -verify-config -config.file=/etc/loki/config.yaml
```

Expected: both commands exit 0 with no unknown processor, OTTL, or OTLP config errors.

### Task 3: Replace the Provisioned Dashboard

**Files:**
- Modify remotely: `/opt/openppp2-otel/dashboards/openppp2-logs.json`

- [ ] **Step 1: Keep stable dashboard identity and fix the base selector**

Keep:

```json
{
  "uid": "openppp2-logs",
  "title": "OpenPPP2 日志",
  "timezone": "Asia/Shanghai",
  "refresh": "10s"
}
```

Use this base selector in all panels so both Collector-default and client-provided casing remain visible:

```logql
{service_name=~"(?i)openppp2"}
```

- [ ] **Step 2: Define dashboard variables**

Create multi-select query variables with `includeAll=true` for:

```text
severity_text
event_name
os_type
scope_name
openppp2_dataplane
openppp2_packet_direction
openppp2_link_state
```

Each query variable uses its concrete label name in this form:

```text
label_values({service_name=~"(?i)openppp2"}, severity_text)
```

Use the same expression with `event_name`, `os_type`, `scope_name`, `openppp2_dataplane`, `openppp2_packet_direction`, and `openppp2_link_state` for the other variables. Create textbox variables `machine_id` and `search`. Set `allValue` to `.*` for label variables and empty string for textboxes. Because `.*` matches the empty label value, All mode retains historical streams created before the new labels existed.

- [ ] **Step 3: Use one shared filter pipeline**

All range and metric queries start from this exact selector and append the two high-cardinality pipeline filters:

```logql
{service_name=~"(?i)openppp2", severity_text=~"${severity_text:regex}", event_name=~"${event_name:regex}", os_type=~"${os_type:regex}", scope_name=~"${scope_name:regex}", openppp2_dataplane=~"${openppp2_dataplane:regex}", openppp2_packet_direction=~"${openppp2_packet_direction:regex}", openppp2_link_state=~"${openppp2_link_state:regex}"}
| machine_id=~".*$machine_id.*"
|= "$search"
```

Specific selections intentionally target logs indexed after rollout. All selections retain historical streams because every variable expands to `.*`, which also matches a missing label.

- [ ] **Step 4: Build the required panels**

Use these exact query shapes. Each query repeats the shared selector so panel behavior cannot drift:

```logql
# Total
sum(count_over_time({service_name=~"(?i)openppp2", severity_text=~"${severity_text:regex}", event_name=~"${event_name:regex}", os_type=~"${os_type:regex}", scope_name=~"${scope_name:regex}", openppp2_dataplane=~"${openppp2_dataplane:regex}", openppp2_packet_direction=~"${openppp2_packet_direction:regex}", openppp2_link_state=~"${openppp2_link_state:regex}"} | machine_id=~".*$machine_id.*" |= "$search" [$__range]))

# Errors
sum(count_over_time({service_name=~"(?i)openppp2", severity_text=~"${severity_text:regex}", event_name=~"${event_name:regex}", os_type=~"${os_type:regex}", scope_name=~"${scope_name:regex}", openppp2_dataplane=~"${openppp2_dataplane:regex}", openppp2_packet_direction=~"${openppp2_packet_direction:regex}", openppp2_link_state=~"${openppp2_link_state:regex}"} | machine_id=~".*$machine_id.*" |= "$search" |= "[ERROR]" [$__range]))

# Trend
sum by (severity_text) (count_over_time({service_name=~"(?i)openppp2", severity_text=~"${severity_text:regex}", event_name=~"${event_name:regex}", os_type=~"${os_type:regex}", scope_name=~"${scope_name:regex}", openppp2_dataplane=~"${openppp2_dataplane:regex}", openppp2_packet_direction=~"${openppp2_packet_direction:regex}", openppp2_link_state=~"${openppp2_link_state:regex}"} | machine_id=~".*$machine_id.*" |= "$search" [$__interval]))

# Event Top 10
topk(10, sum by (event_name) (count_over_time({service_name=~"(?i)openppp2", severity_text=~"${severity_text:regex}", event_name=~"${event_name:regex}", os_type=~"${os_type:regex}", scope_name=~"${scope_name:regex}", openppp2_dataplane=~"${openppp2_dataplane:regex}", openppp2_packet_direction=~"${openppp2_packet_direction:regex}", openppp2_link_state=~"${openppp2_link_state:regex}"} | machine_id=~".*$machine_id.*" |= "$search" [$__range])))

# Failed output packets
sum(count_over_time({service_name=~"(?i)openppp2", severity_text=~"${severity_text:regex}", event_name=~"${event_name:regex}", os_type=~"${os_type:regex}", scope_name=~"${scope_name:regex}", openppp2_dataplane=~"${openppp2_dataplane:regex}", openppp2_packet_direction=~"${openppp2_packet_direction:regex}", openppp2_link_state=~"${openppp2_link_state:regex}"} | machine_id=~".*$machine_id.*" |= "$search" |= "packet_flow direction=output" |= "ok=0" [$__interval]))

# Stop reasons
topk(10, sum by (stop_reason) (count_over_time({service_name=~"(?i)openppp2"} |= "packet_tunnel stop" | regexp `reason=(?P<stop_reason>[a-z_]+)` [$__range])))
```

Create stat panels for total, errors, and error percentage; time-series panels for severity trend and failed output packets; tables for event, platform/component, and stop reason; and a full-width descending logs panel with details enabled.

- [ ] **Step 5: Validate dashboard JSON**

Run:

```bash
jq -e '.uid == "openppp2-logs" and (.panels | length >= 8) and (.templating.list | length == 9)' /opt/openppp2-otel/dashboards/openppp2-logs.json
```

Expected: `true` and exit 0.

### Task 4: Reload and Verify End to End

**Files:**
- Verify remotely: `/opt/openppp2-otel/docker-compose.yml`

- [ ] **Step 1: Restart only Loki and Collector**

Run remotely:

```bash
docker compose -f /opt/openppp2-otel/docker-compose.yml restart loki otel-collector
```

Grafana provisioning watches the dashboard directory; restart Grafana only if UID `openppp2-logs` does not advance to the new version.

- [ ] **Step 2: Wait on health conditions**

Poll, without fixed sleeps, until:

```bash
curl -fsS http://127.0.0.1:3100/ready
curl -fsS http://127.0.0.1:3944/api/health
docker inspect --format '{{.State.Status}} {{.State.OOMKilled}}' openppp2-otel-otel-collector-1
```

Expected: Loki ready, Grafana database ok, Collector `running false`.

- [ ] **Step 3: Send one synthetic OTLP canary log**

Send a log with resource attributes `service.name=OpenPPP2`, `os.type=verification` and log attributes covering event, dataplane, direction, and link state. Use a unique body `grafana_filter_canary_<timestamp>` and severity `INFO`.

Expected: Collector accepts the OTLP request with HTTP 200.

- [ ] **Step 4: Verify labels and structured metadata**

Query Loki until the canary is visible, then verify:

```logql
{service_name="OpenPPP2", severity_text="INFO", event_name="openppp2.verification", os_type="verification"}
```

Expected: one canary entry. `/loki/api/v1/labels` contains the whitelist labels and does not contain `machine_id`, packet number, packet summary, address, or counters.

- [ ] **Step 5: Verify Dashboard and historical compatibility**

Run through Grafana API:

```text
GET /api/dashboards/uid/openppp2-logs
GET /api/datasources/uid/loki/health
```

Expected: dashboard has nine variables and at least eight panels; datasource status is OK. Query a seven-day historical window with `{service_name="OpenPPP2"} |= "packet_flow"` and confirm the prior iOS logs still return.

- [ ] **Step 6: Check post-reload errors**

Run remotely:

```bash
docker logs --since 15m openppp2-otel-otel-collector-1
docker logs --since 15m openppp2-otel-loki-1
```

Expected: no persistent configuration, ingestion, OTTL, error, fatal, panic, or OOM messages. Record one-time shutdown `context canceled` separately if present.

- [ ] **Step 7: Commit the implementation record**

No remote credentials or backup files enter Git. Commit only the implementation plan/status evidence if updated:

```bash
git add -f docs/superpowers/plans/2026-07-15-grafana-log-filtering.md
git commit -m "docs(observability): plan Grafana log filtering rollout"
```
