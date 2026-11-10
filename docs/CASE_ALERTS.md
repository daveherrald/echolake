# Case entry alerts

A dataset case (`cases[]` in `dataset.yaml`) can carry an `alert` block: the entry alert an
investigation starts from. The block is the single source for two things.

- `echolake render-alerts <dataset>` writes the README's "Entry alerts" section between
  `<!-- echolake:alerts:start -->` and `<!-- echolake:alerts:end -->` (appended when absent).
  `--check` fails when the section is stale, for CI.
- `echolake create-lakewatch-alerts <dataset> --catalog <c> --warehouse-id <w> --profile <p>`
  creates the alert in a Lakewatch catalog through the Lakewatch alert API.

The case's Sigma rule stays the portable detection definition. Lakewatch alerts are no longer
produced by converting the rule and letting it fire: rule runs leave signals, system alerts,
and rule names in the catalog that an investigating agent can read, and they break when a rule
is later edited or deleted.

## The block

```yaml
cases:
- id: c2-indicator-entry
  name: Outbound connection to a known C2 indicator
  rule: https://github.com/<owner>/<repo>/blob/main/datasets/<ds>/rules/sigma/<rule>.yml
  disposition: true-positive
  alert:
    title: Outbound connections to known C2 indicator 121.43.243.13 from 192.168.4.233 and 192.168.4.244
    description: '{count} outbound connections ... between {first_seen} and {last_seen}. Low-confidence
      threat-intel seed; treat a match as a pivot, not a verdict.'
    severity: Medium              # Critical, High, Medium, Low, Informational
    anchors: [121.43.243.13, 192.168.4.233, 192.168.4.244]
    evidence:
      table: zeek_conn            # table in the target catalog schema
      where: dst_ip = '121.43.243.13'
      expected_count: 38
      # time_column: time         # default
      # count_tolerance: 0        # default
    # alert_state: OPEN           # default; OPEN or IN_PROGRESS
    # collection: triage_queue    # default alert collection name
    # annotations: {}             # extra alert annotations
```

- `title` and `description` are the alert's whole content. API-created alerts carry no linked
  events, so name the hosts, users, indicators, and time an analyst needs, and give the pivot.
  Do not state the verdict. The title is immutable once created.
- `{count}`, `{first_seen}`, and `{last_seen}` are the only placeholders; they are filled from
  the evidence query at load time. Any other brace is a validation error.
- `evidence.where` is a Databricks SQL predicate over the Lakewatch table: the SQL rendering of
  the case's Sigma rule. It is the machine-checkable record of what the alert covers.
- `anchors` are strings that must each appear in at least one evidence row.

## Loading

`create-lakewatch-alerts` does, per case with an `alert` block:

1. Runs the evidence query (pipe syntax, `FROM <catalog>.<schema>.<table> |> WHERE ... |>
   AGGREGATE ...`) and requires `expected_count` (within `count_tolerance`) and every anchor.
   When the check fails, nothing is created for that case and the command exits nonzero.
2. Finds or creates the alert collection (`POST /api/2.0/lakewatch/alert-collections`).
3. Skips creation when an alert with the same title already exists in that collection, so
   reruns are idempotent; otherwise creates it (`POST /api/2.0/lakewatch/alert-collections/{id}/alerts`).
4. Prints one JSON record per case. With `--manifest-table` and `--load-id` it merges the
   records into `artifact.entry_alerts` of that load_manifests row, replacing any prior record
   for the same case.

`--dry-run` runs only the evidence checks. Auth goes through Databricks CLI profiles
(`--profile`); install the extra with `pip install "echolake[lakewatch]"`.

## Known platform limits (Lakewatch beta, November 2026)

- The alert-collection API is DEVELOPMENT stage (left out of the published SDK, CLI, and docs).
- API-created alerts have no linked events and do not appear in the unfiltered alert list or the
  UI Alerts page, because the list enumerates only rule and datasource parents. They are
  reachable by URL, `alerts:getBySeqId`, or `GET /api/2.0/lakewatch/alerts?parent=alert-collections/<id>`,
  and investigations can open them.
- There is no single-alert delete; deleting the collection removes its alerts.
