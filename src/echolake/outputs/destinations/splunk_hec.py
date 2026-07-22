"""Splunk HTTP Event Collector (HEC) output destination.

Sends replayed events to a Splunk HEC endpoint (Splunk Cloud or self-managed).

Each incoming event is a serialized string. When the string is a JSON object
(the ``jsonl`` output format), its fields are mapped into a HEC event envelope:

    {"time": <epoch>, "host": ..., "source": ..., "sourcetype": ...,
     "index": ..., "event": <raw log line>}

The raw log line sent as ``event`` comes from the configured raw field
(default ``_raw``); if that field is absent the whole object is sent. When the
string is not a JSON object it is sent verbatim as the event, with sourcetype
taken from the per-file metadata or the configured override.

Throughput: set ``max_workers`` > 1 to POST batches concurrently from an
internal thread pool (with backpressure), which is dramatically faster over
high-latency links. Ordering across batches is not preserved in that mode,
which is fine for HEC ingest.

The HEC token is passed in at construction time. The caller is responsible for
reading it from the environment; it is never persisted in config.
"""

import gzip
import json
import logging
import threading
import time as _time_mod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from ..base import OutputDestination

logger = logging.getLogger(__name__)

# Cap the size of a single POST body (pre-compression). Splunk HEC accepts large
# batches, but keeping requests bounded protects memory and improves retryability.
MAX_BATCH_BYTES = 4 * 1024 * 1024  # 4 MB
DEFAULT_MAX_BATCH_EVENTS = 1000
RETRY_STATUS = {429, 500, 502, 503, 504}


class SplunkHECDestination(OutputDestination):
    """Output destination that POSTs events to a Splunk HEC endpoint."""

    def __init__(
        self,
        hec_url: str,
        token: str,
        index: Optional[str] = None,
        verify_ssl: bool = True,
        use_raw_endpoint: bool = False,
        default_host: Optional[str] = None,
        source_override: Optional[str] = None,
        sourcetype_override: Optional[str] = None,
        time_field: str = "_time",
        raw_field: str = "_raw",
        host_field: str = "host",
        source_field: str = "source",
        sourcetype_field: str = "sourcetype",
        batch_size: int = DEFAULT_MAX_BATCH_EVENTS,
        max_retries: int = 5,
        timeout: int = 60,
        max_workers: int = 1,
        dry_run: bool = False,
    ):
        if not REQUESTS_AVAILABLE:
            raise ImportError(
                "requests is required for the splunk_hec destination. Install with: pip install requests"
            )
        if not hec_url:
            raise ValueError("splunk_hec destination requires hec_url")
        if not token and not dry_run:
            raise ValueError(
                "splunk_hec destination requires a token (set the env var named by hec_token_env)"
            )

        self.base_url = hec_url.rstrip("/")
        self.use_raw_endpoint = use_raw_endpoint
        self.endpoint = self._resolve_endpoint(self.base_url, use_raw_endpoint)
        self.token = token
        self.index = index
        self.verify_ssl = verify_ssl
        self.default_host = default_host
        self.source_override = source_override
        self.sourcetype_override = sourcetype_override
        self.time_field = time_field
        self.raw_field = raw_field
        self.host_field = host_field
        self.source_field = source_field
        self.sourcetype_field = sourcetype_field
        self.max_batch_events = max(1, batch_size)
        self.max_retries = max_retries
        self.timeout = timeout
        self.max_workers = max(1, max_workers)
        self.dry_run = dry_run

        # Stats (guarded by _stats_lock in concurrent mode)
        self.events_sent = 0
        self.events_failed = 0
        self.requests_sent = 0
        self._stats_lock = threading.Lock()
        self._errors: List[str] = []
        self._dry_run_preview_remaining = 5  # print at most this many sample envelopes

        # Per-thread requests.Session (Sessions are reused within a thread).
        self._local = threading.local()
        self._sessions: List["requests.Session"] = []
        self._sessions_lock = threading.Lock()

        # Concurrency: internal thread pool with a semaphore for backpressure so
        # the producer blocks instead of queueing unbounded work in memory.
        if self.max_workers > 1 and not dry_run:
            self._executor: Optional[ThreadPoolExecutor] = ThreadPoolExecutor(
                max_workers=self.max_workers
            )
            self._sem: Optional[threading.Semaphore] = threading.Semaphore(self.max_workers * 2)
        else:
            self._executor = None
            self._sem = None

    @staticmethod
    def _resolve_endpoint(base_url: str, use_raw: bool) -> str:
        """Return the full collector endpoint, appending the service path if absent."""
        if "/services/collector" in base_url:
            return base_url
        suffix = "/services/collector/raw" if use_raw else "/services/collector/event"
        return base_url + suffix

    def _session(self):
        """Return a requests.Session local to the calling thread."""
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update({
                "Authorization": f"Splunk {self.token}",
                "Content-Encoding": "gzip",
            })
            self._local.session = s
            with self._sessions_lock:
                self._sessions.append(s)
        return s

    def write(self, source_file_id: str, events: List[str], batch_size: int = 1000,
              metadata: Optional[Dict[str, str]] = None):
        """Build HEC envelopes for events and POST them in bounded batches."""
        file_sourcetype = (metadata or {}).get("sourcetype")

        if self.use_raw_endpoint:
            self._write_raw(events, file_sourcetype)
            return

        buffer: List[str] = []
        buffer_bytes = 0
        for raw in events:
            envelope = self._build_envelope(raw, file_sourcetype)
            line = json.dumps(envelope)
            line_bytes = len(line.encode("utf-8")) + 1

            if buffer and (
                len(buffer) >= self.max_batch_events
                or buffer_bytes + line_bytes > MAX_BATCH_BYTES
            ):
                self._flush_event_batch(buffer)
                buffer = []
                buffer_bytes = 0

            buffer.append(line)
            buffer_bytes += line_bytes

        if buffer:
            self._flush_event_batch(buffer)

    def _build_envelope(self, raw: str, file_sourcetype: Optional[str]) -> Dict:
        """Map a serialized event string to a HEC /event envelope."""
        obj = None
        stripped = raw.strip()
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                obj = None

        envelope: Dict = {}

        if isinstance(obj, dict):
            # Event payload: prefer the raw log line, else the whole object.
            if self.raw_field in obj and obj[self.raw_field] not in (None, ""):
                envelope["event"] = obj[self.raw_field]
            else:
                envelope["event"] = obj

            host = self.default_host or obj.get(self.host_field)
            source = self.source_override or obj.get(self.source_field)
            sourcetype = self.sourcetype_override or obj.get(self.sourcetype_field) or file_sourcetype
            epoch = self._to_epoch(obj.get(self.time_field))
        else:
            envelope["event"] = raw
            host = self.default_host
            source = self.source_override
            sourcetype = self.sourcetype_override or file_sourcetype
            epoch = None

        if epoch is not None:
            envelope["time"] = epoch
        if host:
            envelope["host"] = host
        if source:
            envelope["source"] = source
        if sourcetype:
            envelope["sourcetype"] = sourcetype
        if self.index:
            envelope["index"] = self.index

        return envelope

    def _write_raw(self, events: List[str], file_sourcetype: Optional[str]):
        """POST to /services/collector/raw. Metadata is per-request, not per-event."""
        params = {}
        st = self.sourcetype_override or file_sourcetype
        if st:
            params["sourcetype"] = st
        if self.index:
            params["index"] = self.index
        if self.source_override:
            params["source"] = self.source_override
        if self.default_host:
            params["host"] = self.default_host

        buffer: List[str] = []
        buffer_bytes = 0
        for raw in events:
            line = raw
            stripped = raw.strip()
            if stripped.startswith("{"):
                try:
                    obj = json.loads(stripped)
                    if isinstance(obj, dict) and obj.get(self.raw_field):
                        line = str(obj[self.raw_field])
                except (json.JSONDecodeError, ValueError):
                    pass
            line_bytes = len(line.encode("utf-8")) + 1
            if buffer and (
                len(buffer) >= self.max_batch_events
                or buffer_bytes + line_bytes > MAX_BATCH_BYTES
            ):
                self._submit("\n".join(buffer).encode("utf-8"), len(buffer), params=params)
                buffer = []
                buffer_bytes = 0
            buffer.append(line)
            buffer_bytes += line_bytes
        if buffer:
            self._submit("\n".join(buffer).encode("utf-8"), len(buffer), params=params)

    def _flush_event_batch(self, lines: List[str]):
        """Send a batch of JSON envelope lines to the /event endpoint."""
        if self.dry_run:
            self._preview(lines)
            with self._stats_lock:
                self.events_sent += len(lines)
            return
        body = "\n".join(lines).encode("utf-8")
        self._submit(body, len(lines))

    def _preview(self, lines: List[str]):
        """Print a few sample envelopes in dry-run mode."""
        if self._dry_run_preview_remaining <= 0:
            return
        for line in lines:
            if self._dry_run_preview_remaining <= 0:
                break
            logger.info("HEC dry-run envelope: %s", line)
            print(f"[HEC dry-run] {line}")
            self._dry_run_preview_remaining -= 1

    def _submit(self, body: bytes, event_count: int, params: Optional[Dict] = None):
        """POST synchronously, or hand off to the thread pool with backpressure."""
        if self._executor is None:
            self._post(body, event_count, params)
            return
        self._sem.acquire()
        self._executor.submit(self._post_bg, body, event_count, params)

    def _post_bg(self, body: bytes, event_count: int, params: Optional[Dict]):
        """Thread-pool wrapper: never raise into the worker, record errors instead."""
        try:
            self._post(body, event_count, params)
        except Exception as e:  # noqa: BLE001 - surfaced via stats/close()
            with self._stats_lock:
                self._errors.append(str(e))
        finally:
            self._sem.release()

    def _post(self, body: bytes, event_count: int, params: Optional[Dict] = None):
        """POST a (gzipped) body to the HEC endpoint with retry/backoff."""
        compressed = gzip.compress(body)
        attempt = 0
        session = self._session()
        while True:
            attempt += 1
            try:
                resp = session.post(
                    self.endpoint,
                    data=compressed,
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            except requests.RequestException as e:
                if attempt > self.max_retries:
                    with self._stats_lock:
                        self.events_failed += event_count
                    raise IOError(f"HEC request failed after {self.max_retries} retries: {e}")
                self._backoff(attempt)
                continue

            with self._stats_lock:
                self.requests_sent += 1
            if resp.status_code == 200:
                with self._stats_lock:
                    self.events_sent += event_count
                return
            if resp.status_code in RETRY_STATUS and attempt <= self.max_retries:
                self._backoff(attempt, resp)
                continue

            with self._stats_lock:
                self.events_failed += event_count
            raise IOError(
                f"HEC POST to {self.endpoint} failed: {resp.status_code} {resp.text[:500]}"
            )

    def _backoff(self, attempt: int, resp=None):
        """Sleep with exponential backoff, honoring Retry-After when present."""
        delay = min(2 ** attempt, 60)
        if resp is not None:
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    delay = min(float(retry_after), 120)
                except ValueError:
                    pass
        logger.warning("HEC retry %d/%d, sleeping %.1fs", attempt, self.max_retries, delay)
        _time_mod.sleep(delay)

    @staticmethod
    def _to_epoch(value) -> Optional[float]:
        """Convert an event timestamp to epoch seconds. Returns None if unparseable."""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            try:
                return float(s)
            except ValueError:
                pass
            iso = s.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(iso)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                return None
        return None

    def flush(self):
        """Wait for any in-flight concurrent POSTs to finish."""
        if self._executor is not None:
            # Drain by acquiring all semaphore permits, then release them.
            permits = self.max_workers * 2
            for _ in range(permits):
                self._sem.acquire()
            for _ in range(permits):
                self._sem.release()

    def close(self):
        """Wait for outstanding POSTs, report stats, and close sessions."""
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None
        if self._errors:
            logger.warning("Splunk HEC: %d batch error(s); first: %s",
                           len(self._errors), self._errors[0])
        logger.info(
            "Splunk HEC: %d events sent, %d failed, %d requests",
            self.events_sent, self.events_failed, self.requests_sent,
        )
        with self._sessions_lock:
            for s in self._sessions:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
            self._sessions.clear()
