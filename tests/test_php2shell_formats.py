"""In-place shifting of native web-log formats (php2shell dataset sourcetypes).

Guards the echo.shift_token change that re-emits a strftime-parsed timestamp in
its own textual format instead of ISO 8601, plus the php2shell timestamp-registry
entries. Without the change a CLF or Apache-error line would be rewritten with an
ISO 8601 timestamp, corrupting the log format.
"""

import glob
import gzip
import os

from echolake.core.config import Config, DatasetConfig, OutputConfig, OutputDestinationConfig
from echolake.core.echo import EchoEngine

MANIFEST = """\
metadata:
  name: p2s-formats
  version: 1.0.0
  description: fixture exercising nginx/apache/php-fpm/mitmproxy in-place formats
  timestamp_range:
    earliest: '2026-10-21T20:00:00Z'
    latest: '2026-10-21T20:01:00Z'
    field: line
files:
  bundled:
  - {path: data/nginx.log.gz, format: text, sourcetype: 'nginx:access', schema: native, event_count: 2, log_source: {vendor: nginx, product: nginx, category: web}}
  - {path: data/apache.log.gz, format: text, sourcetype: 'php:apache', schema: native, event_count: 2, log_source: {vendor: Apache, product: mod_php, category: web}}
  - {path: data/fpm.log.gz, format: text, sourcetype: 'php:fpm', schema: native, event_count: 2, log_source: {vendor: PHP, product: PHP-FPM, category: web}}
  - {path: data/mitm.log.gz, format: text, sourcetype: 'mitmproxy:capture', schema: native, event_count: 1, log_source: {vendor: mitmproxy, product: mitmproxy, category: proxy}}
"""

NGINX = (
    '10.0.0.1 - - [21/Oct/2026:20:00:00 +0000] "GET /a HTTP/1.1" 200 1\n'
    '10.0.0.1 - - [21/Oct/2026:20:00:05 +0000] "GET /b HTTP/1.1" 200 2\n'
)
APACHE = (
    '[Wed Oct 21 20:00:00.500000 2026] [php:error] [pid 1] boom\n'
    'AH00558: apache2 startup notice, no timestamp here\n'
)
FPM = (
    '[21-Oct-2026 20:00:03] WARNING: [pool www] child 7 exited with code 70\n'
    '172.17.0.1 -  21/Oct/2026:20:00:04 +0000 "POST /upload.php" 200\n'
)
MITM = 'REQ 1 2026-10-21T20:00:06Z POST http://t/upload.php | headers=aa | body=bb\n'


def _gz(path, text):
    with open(path, "wb") as fh:
        g = gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0)
        g.write(text.encode()); g.close()


def _build(tmp_path):
    ds = tmp_path / "ds"
    (ds / "data").mkdir(parents=True)
    (ds / "dataset.yaml").write_text(MANIFEST)
    _gz(ds / "data" / "nginx.log.gz", NGINX)
    _gz(ds / "data" / "apache.log.gz", APACHE)
    _gz(ds / "data" / "fpm.log.gz", FPM)
    _gz(ds / "data" / "mitm.log.gz", MITM)
    return ds


def _run(tmp_path, shift_payload=False):
    ds = _build(tmp_path)
    out = tmp_path / "out"; out.mkdir()
    cfg_yaml = tmp_path / "c.yaml"
    cfg_yaml.write_text(
        f"""
dataset:
  ref: "local:{ds}"
output:
  destination:
    type: local
    path: {out}
  format: text
echo:
  target_time: '2026-11-01T00:00:00Z'
  prevent_future: false
  shift_payload: {str(shift_payload).lower()}
"""
    )
    cfg = Config.from_file(str(cfg_yaml))
    stats = EchoEngine(cfg).run()
    files = {}
    for f in glob.glob(os.path.join(str(out), "**", "*"), recursive=True):
        if os.path.isfile(f):
            raw = open(f, "rb").read()
            if raw[:2] == b"\x1f\x8b":
                raw = gzip.decompress(raw)
            files[os.path.basename(f)] = raw.decode()
    return files, stats


def test_native_formats_preserved_on_inplace_shift(tmp_path):
    f, stats = _run(tmp_path)
    assert stats.event_count == 7
    nginx = f["nginx.log.gz"]
    # base (20:00:00) maps to the target; CLF format kept, not rewritten to ISO 8601
    assert "[01/Nov/2026:00:00:00 +0000]" in nginx
    assert "[01/Nov/2026:00:00:05 +0000]" in nginx
    assert "2026-11-01T00:00:00" not in nginx  # no ISO 8601 bleed into CLF
    assert '"GET /a HTTP/1.1" 200 1' in nginx   # rest of the line untouched

    apache = f["apache.log.gz"]
    # weekday recomputed for the shifted date (2026-11-01 is a Sunday)
    assert "[Sun Nov 01 00:00:00.500000 2026]" in apache
    assert "AH00558: apache2 startup notice, no timestamp here" in apache  # rides along

    fpm = f["fpm.log.gz"]
    assert "[01-Nov-2026 00:00:03]" in fpm
    assert "172.17.0.1 -  01/Nov/2026:00:00:04 +0000 " in fpm  # bracketless CLF

    mitm = f["mitm.log.gz"]
    assert "REQ 1 2026-11-01T00:00:06Z POST" in mitm
    assert "headers=aa | body=bb" in mitm  # payload untouched


def test_inplace_stats_include_untimestamped_lines_with_payload_shift(tmp_path):
    _, stats = _run(tmp_path, shift_payload=True)
    assert stats.event_count == 7
    assert stats.events_modified == 6
