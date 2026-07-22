"""Shift timestamps embedded in _raw text fields.

Applies the same time shift used for _time to all recognized timestamp
patterns found in the _raw field of CSV exports.

Covers 14 timestamp format families:
  1.  ISO 8601       (stream-*, suricata, XmlWinEventLog, CloudTrail, ELB)
  2.  FortiGate KV   (fgt_traffic, fgt_event, fgt_utm)
  3.  Syslog BSD     (FortiGate syslog headers, linux_secure, cisco:asa)
  4.  US date        (WinEventLog-*, winregistry, auditd human-readable)
  5.  YYYY-MM-DD     (IIS W3C, symantec-ep-*)
  6.  Unix epoch     (nessus-scan JSON)
  7.  PAN-OS date    (pan:traffic, pan:threat)
  8.  CLF/Apache     (access_combined, aws:s3:accesslogs)
  9.  Apache error   (apache_error)
  10. ctime          (osquery calendarTime, syslog fst/fet)
  11. Linux audit    (linux_audit, auditd raw)
  12. Compact date   (aws:rds:audit)
  13. Epoch ms JSON  (ms:aad:signin, ms:aad:audit, code42)
  14. .NET JSON date (ms:o365:reporting:messagetrace)
"""

import calendar
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from dateutil import parser as date_parser

# Month abbreviation lookup
_MONTH_NUM = {name: num for num, name in enumerate(calendar.month_abbr) if name}
_MONTH_ABBR = list(calendar.month_abbr)  # index 0='', 1='Jan', ..., 12='Dec'

# ---------------------------------------------------------------------------
# Compiled regex patterns (priority order)
# ---------------------------------------------------------------------------

# 1. ISO 8601
_ISO8601_RE = re.compile(
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'
)

# 2. FortiGate: date=YYYY-MM-DD time=HH:MM:SS
_FORTIGATE_RE = re.compile(
    r'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2})'
)

# 3. Syslog BSD: Mon DD HH:MM:SS (at line start)
_SYSLOG_RE = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s{1,2}(\d{1,2})\s(\d{2}:\d{2}:\d{2})',
    re.MULTILINE,
)

# 4. US date: MM/DD/YYYY HH:MM:SS[.fff][ AM/PM]
_US_DATE_RE = re.compile(
    r'(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)(\s+[AP]M)?'
)

# 5. YYYY-MM-DD HH:MM:SS standalone (IIS) – lookbehind avoids ISO 8601
_DATETIME_RE = re.compile(
    r'(?<![T\d])(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})'
)

# 6. Unix epoch in JSON context: "timestamp": 1472056400
_EPOCH_RE = re.compile(
    r'"(?:timestamp|time|_time)"\s*:\s*(\d{10})(?!\d)'
)

# 7. PAN-OS date: YYYY/MM/DD HH:MM:SS (multiple per row in pan:traffic/threat)
_PANOS_RE = re.compile(
    r'(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})'
)

# 8. CLF / Apache access: [DD/Mon/YYYY:HH:MM:SS +ZZZZ]
_CLF_RE = re.compile(
    r'\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})\s+([+-]\d{4})\]'
)

# 9. Apache error: [Dow Mon DD HH:MM:SS YYYY] or [Dow Mon DD HH:MM:SS.uuuuuu YYYY]
_APACHE_ERR_RE = re.compile(
    r'\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+'
    r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(\d{1,2})\s+'
    r'(\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s+'
    r'(\d{4})\]'
)

# 10. ctime: Dow Mon DD HH:MM:SS YYYY [TZ] (osquery calendarTime, syslog fst/fet)
_CTIME_RE = re.compile(
    r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)(?:,?\s+)'
    r'(\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})'
    r'(?:\s+[A-Z]{1,5})?'
    r'|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+'
    r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})'
    r'(?:\s+[A-Z]{1,5})?'
)

# 11. Linux audit epoch: audit(1504220400.425:940437)
_AUDIT_EPOCH_RE = re.compile(
    r'audit\((\d{10})\.(\d{3}):\d+\)'
)

# 12. Compact datetime: YYYYMMDD HH:MM:SS (RDS audit)
_COMPACT_DT_RE = re.compile(
    r'(?<!\d)(\d{8})\s+(\d{2}:\d{2}:\d{2})(?!\d)'
)

# 13. Unix epoch milliseconds in JSON: "field": 1534777868745
_EPOCH_MS_RE = re.compile(
    r'"(?:timestamp|time|_time|[a-zA-Z]*[Tt]imestamp|[a-zA-Z]*[Tt]ime(?:InMillis|Millis)?|detectionTimestamp|activityDateInMillis|signinDateTimeInMillis)"\s*:\s*(\d{13})(?!\d)'
)

# 14. .NET JSON date: /Date(1534777825332)/
_DOTNET_DATE_RE = re.compile(
    r'/Date\((\d{13})\)/'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shift_ts(
    original_ts: datetime,
    original_base: datetime,
    new_base: datetime,
    delta_factor: float,
    ceiling: Optional[datetime],
) -> datetime:
    """Compute shifted timestamp using the same formula as echo.py."""
    delta = original_ts - original_base
    new_delta = delta * delta_factor
    new_ts = new_base + new_delta
    if ceiling and new_ts > ceiling:
        new_ts = ceiling
    return new_ts


def _format_iso8601(dt: datetime, original: str) -> str:
    """Re-format *dt* to match the exact sub-second / tz style of *original*."""
    base = dt.strftime('%Y-%m-%dT%H:%M:%S')

    # Fractional seconds — preserve original digit count
    frac_m = re.search(r'\.(\d+)', original)
    if frac_m:
        n = len(frac_m.group(1))
        us = dt.microsecond
        if n <= 6:
            frac = f'{us:06d}'[:n]
        else:
            # >6 digits (nanoseconds) — pad microseconds with trailing zeros
            frac = f'{us:06d}' + '0' * (n - 6)
        base += '.' + frac

    # Timezone — reproduce exact style (Z, +HH:MM, +HHMM, -0600, etc.)
    tz_m = re.search(r'(Z|[+-]\d{2}:?\d{2})$', original)
    if tz_m:
        tz_str = tz_m.group(1)
        if tz_str == 'Z':
            base += 'Z'
        else:
            offset = dt.utcoffset()
            total = int(offset.total_seconds()) if offset else 0
            sign = '+' if total >= 0 else '-'
            h, rem = divmod(abs(total), 3600)
            m = rem // 60
            if ':' in tz_str:
                base += f'{sign}{h:02d}:{m:02d}'
            else:
                base += f'{sign}{h:02d}{m:02d}'

    return base


# ---------------------------------------------------------------------------
# Per-pattern match handlers
# ---------------------------------------------------------------------------

def _handle_iso8601(m, original_base, new_base, delta_factor, ceiling):
    original_str = m.group(0)
    original_ts = date_parser.isoparse(original_str)
    if original_ts.tzinfo is None:
        original_ts = original_ts.replace(tzinfo=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    # Convert back to the original timezone so the offset is preserved
    new_ts = new_ts.astimezone(original_ts.tzinfo)
    return _format_iso8601(new_ts, original_str)


def _handle_fortigate(m, original_base, new_base, delta_factor, ceiling):
    date_str, time_str = m.group(1), m.group(2)
    original_ts = datetime.strptime(
        f'{date_str} {time_str}', '%Y-%m-%d %H:%M:%S'
    ).replace(tzinfo=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    return f'date={new_ts.strftime("%Y-%m-%d")} time={new_ts.strftime("%H:%M:%S")}'


def _handle_syslog(m, original_base, new_base, delta_factor, ceiling):
    month_name, day_str, time_str = m.group(1), m.group(2), m.group(3)
    month = _MONTH_NUM[month_name]
    day = int(day_str)
    h, mi, s = (int(x) for x in time_str.split(':'))
    year = original_base.year
    original_ts = datetime(year, month, day, h, mi, s, tzinfo=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    return f'{_MONTH_ABBR[new_ts.month]} {new_ts.day:>2d} {new_ts.strftime("%H:%M:%S")}'


def _handle_us_date(m, original_base, new_base, delta_factor, ceiling):
    date_str = m.group(1)   # MM/DD/YYYY
    time_str = m.group(2)   # HH:MM:SS[.fff]
    ampm = m.group(3)       # ' AM' / ' PM' / None

    month, day, year = (int(x) for x in date_str.split('/'))

    time_parts = time_str.split('.')
    hms = time_parts[0]
    h, mi, s = (int(x) for x in hms.split(':'))
    frac = time_parts[1] if len(time_parts) > 1 else None

    # Convert 12-hour to 24-hour if AM/PM present
    if ampm:
        ap = ampm.strip()
        if h == 12:
            if ap == 'AM':
                h = 0  # 12 AM = midnight
        elif h < 12 and ap == 'PM':
            h += 12
        # h > 12 with AM/PM: treat as already 24-hour

    us = int(frac.ljust(6, '0')[:6]) if frac else 0
    original_ts = datetime(year, month, day, h, mi, s, us, tzinfo=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)

    new_date = f'{new_ts.month:02d}/{new_ts.day:02d}/{new_ts.year:04d}'
    if ampm:
        nh = new_ts.hour
        period = 'AM' if nh < 12 else 'PM'
        display_h = nh % 12 or 12
        new_time = f'{display_h:02d}:{new_ts.minute:02d}:{new_ts.second:02d}'
        if frac:
            new_frac = f'{new_ts.microsecond:06d}'[:len(frac)]
            new_time += f'.{new_frac}'
        return f'{new_date} {new_time} {period}'
    else:
        new_time = f'{new_ts.hour:02d}:{new_ts.minute:02d}:{new_ts.second:02d}'
        if frac:
            new_frac = f'{new_ts.microsecond:06d}'[:len(frac)]
            new_time += f'.{new_frac}'
        return f'{new_date} {new_time}'


def _handle_datetime(m, original_base, new_base, delta_factor, ceiling):
    date_str, time_str = m.group(1), m.group(2)
    original_ts = datetime.strptime(
        f'{date_str} {time_str}', '%Y-%m-%d %H:%M:%S'
    ).replace(tzinfo=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    return f'{new_ts.strftime("%Y-%m-%d")} {new_ts.strftime("%H:%M:%S")}'


def _handle_epoch(m, original_base, new_base, delta_factor, ceiling):
    epoch_str = m.group(1)
    original_ts = datetime.fromtimestamp(int(epoch_str), tz=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    new_epoch = str(int(new_ts.timestamp()))
    # Replace only the digit group, keeping surrounding JSON syntax
    return m.group(0).replace(epoch_str, new_epoch, 1)


def _handle_panos(m, original_base, new_base, delta_factor, ceiling):
    date_str, time_str = m.group(1), m.group(2)
    original_ts = datetime.strptime(
        f'{date_str} {time_str}', '%Y/%m/%d %H:%M:%S'
    ).replace(tzinfo=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    return f'{new_ts.strftime("%Y/%m/%d")} {new_ts.strftime("%H:%M:%S")}'


def _handle_clf(m, original_base, new_base, delta_factor, ceiling):
    dt_str = m.group(1)    # DD/Mon/YYYY:HH:MM:SS
    tz_str = m.group(2)    # +0000
    original_ts = datetime.strptime(
        f'{dt_str} {tz_str}', '%d/%b/%Y:%H:%M:%S %z'
    )
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    new_ts = new_ts.astimezone(original_ts.tzinfo)
    return f'[{new_ts.strftime("%d/%b/%Y:%H:%M:%S")} {tz_str}]'


def _handle_apache_err(m, original_base, new_base, delta_factor, ceiling):
    month_name = m.group(1)
    day = int(m.group(2))
    time_str = m.group(3)
    frac = m.group(4)  # may be None
    year = int(m.group(5))
    month = _MONTH_NUM[month_name]
    h, mi, s = (int(x) for x in time_str.split(':'))
    us = int(frac.ljust(6, '0')[:6]) if frac else 0
    original_ts = datetime(year, month, day, h, mi, s, us, tzinfo=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    dow = calendar.day_abbr[new_ts.weekday()]
    base = f'[{dow} {_MONTH_ABBR[new_ts.month]} {new_ts.day:02d} {new_ts.strftime("%H:%M:%S")}'
    if frac:
        new_frac = f'{new_ts.microsecond:06d}'[:len(frac)]
        base += f'.{new_frac}'
    base += f' {new_ts.year}]'
    return base


def _handle_ctime(m, original_base, new_base, delta_factor, ceiling):
    # Group 1: RFC-2822-ish "DD Mon YYYY HH:MM:SS" (from "Dow, DD Mon YYYY HH:MM:SS")
    # Group 2: ctime "Mon DD HH:MM:SS YYYY" (from "Dow Mon DD HH:MM:SS YYYY")
    if m.group(1):
        dt_str = m.group(1)
        original_ts = datetime.strptime(dt_str, '%d %b %Y %H:%M:%S').replace(
            tzinfo=timezone.utc
        )
        new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
        dow = calendar.day_abbr[new_ts.weekday()]
        # Preserve the comma style from original
        orig_text = m.group(0)
        sep = ', ' if ', ' in orig_text[:5] else ' '
        result = f'{dow}{sep}{new_ts.day} {_MONTH_ABBR[new_ts.month]} {new_ts.year} {new_ts.strftime("%H:%M:%S")}'
        # Re-append timezone if present
        tz_m = re.search(r'\s+([A-Z]{1,5})$', orig_text)
        if tz_m:
            result += f' {tz_m.group(1)}'
        return result
    else:
        dt_str = m.group(2)
        original_ts = datetime.strptime(dt_str, '%b %d %H:%M:%S %Y').replace(
            tzinfo=timezone.utc
        )
        new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
        dow = calendar.day_abbr[new_ts.weekday()]
        result = f'{dow} {_MONTH_ABBR[new_ts.month]} {new_ts.day:>2d} {new_ts.strftime("%H:%M:%S")} {new_ts.year}'
        orig_text = m.group(0)
        tz_m = re.search(r'\s+([A-Z]{1,5})$', orig_text)
        if tz_m:
            result += f' {tz_m.group(1)}'
        return result


def _handle_audit_epoch(m, original_base, new_base, delta_factor, ceiling):
    epoch_str = m.group(1)
    ms_str = m.group(2)
    us = int(ms_str) * 1000
    original_ts = datetime.fromtimestamp(int(epoch_str), tz=timezone.utc).replace(
        microsecond=us
    )
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    new_ms = f'{new_ts.microsecond // 1000:03d}'
    # Preserve the serial number from the original
    return m.group(0).replace(
        f'{epoch_str}.{ms_str}',
        f'{int(new_ts.timestamp())}.{new_ms}',
        1,
    )


def _handle_compact_dt(m, original_base, new_base, delta_factor, ceiling):
    date_str = m.group(1)  # YYYYMMDD
    time_str = m.group(2)  # HH:MM:SS
    original_ts = datetime.strptime(
        f'{date_str} {time_str}', '%Y%m%d %H:%M:%S'
    ).replace(tzinfo=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    return f'{new_ts.strftime("%Y%m%d")} {new_ts.strftime("%H:%M:%S")}'


def _handle_epoch_ms(m, original_base, new_base, delta_factor, ceiling):
    epoch_ms_str = m.group(1)
    epoch_s = int(epoch_ms_str) / 1000.0
    original_ts = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    new_epoch_ms = str(int(new_ts.timestamp() * 1000))
    return m.group(0).replace(epoch_ms_str, new_epoch_ms, 1)


def _handle_dotnet_date(m, original_base, new_base, delta_factor, ceiling):
    epoch_ms_str = m.group(1)
    epoch_s = int(epoch_ms_str) / 1000.0
    original_ts = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
    new_ts = _shift_ts(original_ts, original_base, new_base, delta_factor, ceiling)
    new_epoch_ms = str(int(new_ts.timestamp() * 1000))
    return f'/Date({new_epoch_ms})/'


# Named pattern tuples for sourcetype mapping
_P_ISO8601 =    (_ISO8601_RE,       _handle_iso8601)
_P_FORTIGATE =  (_FORTIGATE_RE,     _handle_fortigate)
_P_AUDIT =      (_AUDIT_EPOCH_RE,   _handle_audit_epoch)
_P_SYSLOG =     (_SYSLOG_RE,        _handle_syslog)
_P_US_DATE =    (_US_DATE_RE,       _handle_us_date)
_P_CLF =        (_CLF_RE,           _handle_clf)
_P_APACHE_ERR = (_APACHE_ERR_RE,    _handle_apache_err)
_P_CTIME =      (_CTIME_RE,         _handle_ctime)
_P_PANOS =      (_PANOS_RE,         _handle_panos)
_P_DATETIME =   (_DATETIME_RE,      _handle_datetime)
_P_COMPACT =    (_COMPACT_DT_RE,    _handle_compact_dt)
_P_EPOCH_MS =   (_EPOCH_MS_RE,      _handle_epoch_ms)
_P_DOTNET =     (_DOTNET_DATE_RE,   _handle_dotnet_date)
_P_EPOCH =      (_EPOCH_RE,         _handle_epoch)

# All patterns (priority order) - used as fallback for unknown sourcetypes
_ALL_PATTERNS = [
    _P_ISO8601, _P_FORTIGATE, _P_AUDIT, _P_SYSLOG, _P_US_DATE,
    _P_CLF, _P_APACHE_ERR, _P_CTIME, _P_PANOS, _P_DATETIME,
    _P_COMPACT, _P_EPOCH_MS, _P_DOTNET, _P_EPOCH,
]

# Sourcetype → relevant patterns (only run what's needed)
# Empty list = no _raw timestamps, skip shifting entirely
_SOURCETYPE_PATTERNS = {
    # === Stream (ISO 8601) ===
    'stream:http':  [_P_ISO8601],
    'stream:dns':   [_P_ISO8601],
    'stream:dhcp':  [_P_ISO8601],
    'stream:icmp':  [_P_ISO8601],
    'stream:ip':    [_P_ISO8601],
    'stream:ldap':  [_P_ISO8601],
    'stream:mapi':  [_P_ISO8601],
    'stream:sip':   [_P_ISO8601],
    'stream:smb':   [_P_ISO8601],
    'stream:snmp':  [_P_ISO8601],
    'stream:tcp':   [_P_ISO8601],
    'stream:ftp':   [_P_ISO8601],
    'stream:arp':   [_P_ISO8601],
    'stream:mysql': [_P_ISO8601],
    'stream:smtp':  [_P_ISO8601],
    'stream:udp':   [_P_ISO8601],
    'stream:irc':   [_P_ISO8601],
    'stream:igmp':  [_P_ISO8601],
    # === Suricata / IDS ===
    'suricata':     [_P_ISO8601],
    # === Windows (XML → ISO, EventLog → US date) ===
    'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational': [_P_ISO8601],
    'WinEventLog:Security':    [_P_US_DATE],
    'WinEventLog:Application': [_P_US_DATE],
    'WinEventLog:System':      [_P_US_DATE],
    'WinEventLog:Directory-Service': [_P_US_DATE],
    'WinEventLog:Microsoft-Windows-PowerShell/Operational': [_P_US_DATE],
    'WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL': [_P_US_DATE],
    'WinEventLog:Microsoft-Windows-AppLocker/Packaged app-Execution': [_P_US_DATE],
    'WinRegistry':  [_P_US_DATE],
    # === FortiGate ===
    # Splunk's BOTS/CIM sourcetypes use the fgt_* names; keep the legacy
    # fortigate_* aliases too. The syslog header AND the embedded
    # date=YYYY-MM-DD time=HH:MM:SS fields both need shifting.
    'fortigate_event':   [_P_FORTIGATE, _P_SYSLOG],
    'fortigate_traffic': [_P_FORTIGATE, _P_SYSLOG],
    'fortigate_utm':     [_P_FORTIGATE, _P_SYSLOG],
    'fgt_event':         [_P_FORTIGATE, _P_SYSLOG],
    'fgt_traffic':       [_P_FORTIGATE, _P_SYSLOG],
    'fgt_utm':           [_P_FORTIGATE, _P_SYSLOG],
    # === IIS ===
    'iis':          [_P_DATETIME],
    # === Nessus ===
    'nessus:scan':  [_P_EPOCH],
    # === Palo Alto ===
    'pan:traffic':  [_P_SYSLOG, _P_PANOS],
    'pan:threat':   [_P_SYSLOG, _P_PANOS],
    'pan:system':   [_P_SYSLOG],
    # === Symantec EP ===
    'symantec:ep:security:file':    [_P_DATETIME],
    'symantec:ep:traffic:file':     [_P_DATETIME],
    'symantec:ep:agent:file':       [_P_DATETIME],
    'symantec:ep:agt_system:file':  [_P_DATETIME],
    'symantec:ep:behavior:file':    [_P_DATETIME],
    'symantec:ep:packet:file':      [_P_DATETIME],
    'symantec:ep:scan:file':        [_P_DATETIME],
    'symantec:ep:scm_system:file':  [_P_DATETIME],
    'symantec:ep:risk:file':        [_P_DATETIME],
    # === Apache ===
    'access_combined':              [_P_CLF],
    'WebLogic_Access_Combined':     [_P_CLF],
    'apache_error':                 [_P_APACHE_ERR],
    'weblogic_stdout':              [_P_ISO8601],
    # === Linux/Unix ===
    'syslog':        [_P_SYSLOG, _P_CTIME],
    'linux_secure':  [_P_SYSLOG],
    'auditd':        [_P_US_DATE],
    'linux_audit':   [_P_AUDIT],
    'linux:audit':   [_P_AUDIT],
    'cisco:asa':     [_P_SYSLOG],
    # === osquery ===
    'osquery_results':  [_P_CTIME, _P_EPOCH],
    'osquery_info':     [_P_CTIME, _P_EPOCH],
    'osquery:results':  [_P_CTIME, _P_EPOCH],
    'osquery:info':     [_P_CTIME, _P_EPOCH],
    'osquery_warning':  [],
    'osquery:warning':  [],
    # === AWS ===
    'aws:cloudtrail':           [_P_ISO8601],
    'aws:cloudwatch':           [_P_ISO8601],
    'aws:cloudwatchlogs':       [_P_ISO8601],
    'aws:cloudwatch:guardduty': [_P_ISO8601],
    'aws:elb:accesslogs':       [_P_ISO8601],
    'aws:s3:accesslogs':        [_P_CLF],
    'aws:rds:audit':            [_P_COMPACT],
    'aws:rds:error':            [_P_ISO8601],
    'aws:config:rule':          [_P_ISO8601],
    'aws:description':          [_P_ISO8601],
    'aws:cloudwatchlogs:vpcflow': [],  # bare epochs, not safely matchable
    # === Microsoft / O365 ===
    'ms:o365:management':       [_P_ISO8601],
    'o365:management:activity': [_P_ISO8601],
    'ms:o365:reporting:messagetrace': [_P_ISO8601, _P_DOTNET],
    'ms:aad:signin':            [_P_ISO8601, _P_EPOCH_MS],
    'ms:aad:audit':             [_P_ISO8601, _P_EPOCH_MS],
    # === Code42 ===
    'code42:security':  [_P_ISO8601, _P_EPOCH, _P_EPOCH_MS, _P_CTIME],
    'code42:api':       [_P_ISO8601],
    'code42:computer':  [_P_ISO8601],
    'code42:org':       [_P_ISO8601],
    'code42:user':      [_P_ISO8601],
    # === MySQL (structured stats — no _raw timestamps) ===
    'mysql:connection:stats': [],
    'mysql:database':         [],
    'mysql:errorLog':         [_P_ISO8601],
    'mysql:instance:stats':   [],
    'mysql:server:stats':     [],
    'mysql:status':           [],
    'mysql:table_io_waits_summary_by_index_usage': [],
    'mysql:tableStatus':      [],
    'mysql:transaction:details': [],
    'mysql:transaction:stats':  [],
    'mysql:user':             [],
    'mysql:variables':        [],
    'mysqld-8':               [],
    # === Performance / Metrics (no timestamps in _raw) ===
    'Perfmon:CPU':               [],
    'Perfmon:LogicalDisk':       [],
    'Perfmon:Memory':            [],
    'Perfmon:Network':           [],
    'Perfmon:Network_Interface': [],
    'Perfmon:NTDS':              [],
    'Perfmon:PhysicalDisk':      [],
    'Perfmon:Process':           [],
    'Perfmon:Processor':         [],
    'Perfmon:System':            [],
    'PerfmonMk:Process':         [],
    'collectd':                  [],
    'cpu':     [],
    'df':      [],
    'iostat':  [],
    'vmstat':  [],
    'top':     [],
    'ps':      [],
    'netstat': [],
    'who':     [],
    'time':    [],
    'bandwidth': [],
    # === System inventory (no timestamps in _raw) ===
    'WinHostMon':       [],
    'hardware':         [],
    'interfaces':       [],
    'openPorts':        [],
    'package':          [],
    'protocol':         [],
    'lastlog':          [],
    'lsof':             [],
    'usersWithLoginPrivs': [],
    'ActiveDirectory':  [],
    'MSAD:NT6:Health':  [],
    'MSAD:NT6:SiteInfo': [],
    'Linux:SELinuxConfig': [],
    'WindowsUpdateLog': [],
    'Powershell:ScriptExecutionSummary': [],
    'Script:InstalledApps': [],
    'Script:ListeningPorts': [],
    'Script:GetEndpointInfo': [],
    'Unix:ListeningPorts': [],
    'Unix:Service':     [],
    'Unix:SSHDConfig':  [],
    'Unix:Update':      [],
    'Unix:Uptime':      [],
    'Unix:UserAccounts': [],
    'Unix:Version':     [],
    'web_ping':         [],
    'csp-violation':    [],
    'ess_content_importer': [],
    'config_file':      [],
    'dmesg':            [],
    'dpkg':             [],
    'alternatives':     [],
    'bootstrap':        [],
    'cloud-init':       [],
    'cloud-init-output': [],
    'amazon-ssm-agent': [],
    'amazon-ssm-agent-too_small': [],
    'bash_history':     [],
    'history-2':        [],
    'localhost-5':      [],
    'out-3':            [],
    'errors':           [],
    'error-too_small':  [],
    'errors-too_small': [],
    'cron-too_small':   [],
    'maillog-too_small': [],
    'yum-too_small':    [],
}


def _get_patterns_for_sourcetype(sourcetype: Optional[str]):
    """Return the pattern list for a given sourcetype.

    Exact match first, then prefix match for families like WinEventLog:*,
    XmlWinEventLog:*, stream:*, etc.  Falls back to a small default set.
    """
    if sourcetype and sourcetype in _SOURCETYPE_PATTERNS:
        return _SOURCETYPE_PATTERNS[sourcetype]

    # Prefix-based matching for sourcetype families
    if sourcetype:
        for prefix in ('stream:', 'WinEventLog:', 'XmlWinEventLog:',
                        'Perfmon:', 'PerfmonMk:', 'Unix:', 'Script:',
                        'symantec:ep:', 'mysql:', 'aws:', 'code42:',
                        'ms:aad:', 'o365:', 'ms:o365:'):
            if sourcetype.startswith(prefix):
                # Find any entry with this prefix
                for key, pats in _SOURCETYPE_PATTERNS.items():
                    if key.startswith(prefix):
                        return pats
                break

    # Fallback: small default set (covers most common cases). FortiGate's
    # date=.. time=.. is listed before _P_DATETIME so it claims that span
    # instead of the generic datetime pattern. _P_EPOCH is safe here because
    # its regex only matches epochs behind a "timestamp"/"time"/"_time" JSON
    # key, so bare 10-digit numbers are not touched.
    return [_P_ISO8601, _P_FORTIGATE, _P_SYSLOG, _P_US_DATE, _P_EPOCH, _P_DATETIME]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def shift_raw_timestamps(
    raw_text: str,
    original_base: datetime,
    new_base: datetime,
    delta_factor: float = 1.0,
    ceiling: Optional[datetime] = None,
    sourcetype: Optional[str] = None,
) -> str:
    """Shift all recognized timestamps in *raw_text* by the echo delta.

    Uses the same shift formula as the main echo engine::

        new_ts = new_base + (original_ts - original_base) * delta_factor

    Parameters
    ----------
    raw_text : str
        The ``_raw`` field value (original event text).
    original_base : datetime
        Earliest original timestamp (same value used for ``_time`` shift).
    new_base : datetime
        Target base timestamp (same value used for ``_time`` shift).
    delta_factor : float
        Time-delta multiplier (default 1.0 = real-time).
    ceiling : datetime, optional
        Maximum allowed timestamp (prevent-future cap).
    sourcetype : str, optional
        Sourcetype identifier — enables running only relevant patterns.

    Returns
    -------
    str
        *raw_text* with all recognized timestamps shifted.
    """
    patterns = _get_patterns_for_sourcetype(sourcetype)

    # Fast path: sourcetype known to have no _raw timestamps
    if not patterns:
        return raw_text

    # Collect replacements: (start, end, replacement_text)
    replacements: List[Tuple[int, int, str]] = []
    used_ranges: List[Tuple[int, int]] = []

    for regex, handler in patterns:
        for m in regex.finditer(raw_text):
            start, end = m.start(), m.end()
            # Skip if overlapping with an already-matched higher-priority range
            if any(not (end <= us or start >= ue) for us, ue in used_ranges):
                continue
            try:
                replacement = handler(m, original_base, new_base, delta_factor, ceiling)
                replacements.append((start, end, replacement))
                used_ranges.append((start, end))
            except (ValueError, OverflowError, KeyError):
                continue

    if not replacements:
        return raw_text

    # Replace right-to-left to preserve character positions
    replacements.sort(key=lambda r: r[0], reverse=True)
    result = raw_text
    for start, end, replacement in replacements:
        result = result[:start] + replacement + result[end:]

    return result
