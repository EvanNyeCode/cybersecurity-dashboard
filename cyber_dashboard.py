#!/usr/bin/env python3
"""
Cybersecurity Alert Dashboard
Local Windows security assessment dashboard with a hardened localhost API.

Design goals:
- Gather real security posture information from the current PC.
- Render a browser-based dashboard with cumulative risk scoring and findings.
- Remediate only allowlisted issues through explicit user action.
- Avoid remote dependencies, arbitrary command execution, and unsafe rendering patterns.

This project intentionally uses only the Python standard library so it can run on a
fresh Windows PC with Python installed.
"""

from __future__ import annotations

import ctypes
import datetime as _dt
import json
import os
import platform
import random
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from dataclasses import dataclass, asdict
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

try:
    import winreg  # type: ignore
except Exception:  # pragma: no cover - not available on non-Windows platforms
    winreg = None  # type: ignore

APP_NAME = "Cybersecurity Alert Dashboard"
APP_VERSION = "1.8.2"
HOST = "127.0.0.1"
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
AUDIT_LOG = LOG_DIR / "audit.log"
MAX_JSON_BODY_BYTES = 16_384
REQUEST_TIMEOUT_SECONDS = 25
DEFAULT_SCAN_TIMEOUT_SECONDS = 35

SEVERITY_IMPACT = {
    "critical": 25,
    "high": 16,
    "medium": 9,
    "low": 4,
    "info": 0,
}

SAFE_FIX_ALL_ACTIONS = {
    # Fix-all includes only free, allowlisted remediations. The UI still asks
    # for confirmation before applying them as a batch. No paid upgrades or
    # third-party tools are invoked by any remediation.
    "enable_firewall",
    "harden_firewall_default_inbound",
    "block_risky_inbound_ports",
    "disable_network_discovery_firewall_group",
    "disable_file_printer_sharing_firewall_group",
    "enable_defender_realtime",
    "enable_defender_cloud",
    "enable_defender_pua",
    "update_defender_signatures",
    "run_defender_quick_scan",
    "enable_controlled_folder_access",
    "enable_defender_network_protection",
    "enable_defender_asr_baseline",
    "remove_all_defender_exclusions",
    "enable_smartscreen",
    "disable_rdp",
    "disable_smb1",
    "enable_uac",
    "disable_guest",
    "disable_builtin_administrator",
    "enable_autorun_protection",
    "disable_winrm",
    "disable_remote_registry",
    "enable_file_extensions",
    "disable_remote_assistance",
    "enable_lsa_protection",
    "enable_memory_integrity",
    "set_machine_password_policy",
    "set_powershell_remote_signed",
    "disable_powershell_v2",
    "disable_insecure_guest_auth",
    "enable_restrict_anonymous",
    "enable_wdigest_protection",
    "set_lm_compatibility_level",
    "enable_blank_password_restriction",
    "enable_smb_signing",
    "disable_llmnr",
    "enable_windows_update_services",
    "start_security_services",
    "run_windows_update_scan",
    "schedule_restart_60",
    "disable_telnet_service",
    "disable_ftp_service",
    "disable_snmp_service",
    "clean_suspicious_hosts",
    "disable_icmp_echo_firewall_rules",
    "disable_remote_management_firewall_rules",
    "enable_firewall_stealth_mode",
    "enforce_uac_secure_desktop",
    "disable_auto_admin_logon",
    "enable_no_lm_hash",
    "limit_cached_logons",
    "disable_password_reveal",
    "harden_tls_defaults",
    "block_office_internet_macros",
    "disable_delivery_optimization_internet_peer",
    "disable_advertising_id",
    "disable_clipboard_cloud",
    "harden_autoplay_policy",
    "disable_web_search_in_start",
    "harden_event_log_retention",
    "enable_defender_expanded_asr",
    "enable_failed_logon_audit",
    "enable_process_creation_auditing",
    "enable_powershell_logging",
    "enable_defender_deep_scanning",
    "enable_firewall_logging",
    "disable_network_discovery_services",
    "disable_netbios_over_tcpip",
    "disable_print_spooler_if_no_physical_printers",
    "disable_always_install_elevated",
    "restrict_remote_sam",
    "restrict_anonymous_sam",
    "disable_domain_credential_storage",
    "enforce_ctrl_alt_del",
    "enable_edge_browser_hardening",
    "enable_chrome_browser_hardening",
    "ensure_windows_update_auto",
    "disable_lmhosts_lookup",
    "enforce_screen_lock_timeout",
    "disable_location_tracking",
    "disable_activity_history",
    "reduce_diagnostics_telemetry",
    "disable_tailored_experiences",
    "disable_app_launch_tracking",
    "disable_lock_screen_camera",
    "disable_lock_screen_notifications",
    "disable_windows_script_host",
    "enable_defender_scheduled_scan",
    "enable_expanded_audit_policy",
    "disable_openssh_server",
    "disable_iis_services",
    "disable_function_discovery_services",
    "disable_teredo_tunneling",
    "harden_tcpip_stack",
    "disable_cdrom_autorun",
    "disable_windows_error_reporting",
    "disable_consumer_experiences",
    # v10 deeper hardening controls
    "disable_winrm_basic_auth",
    "disable_winrm_unencrypted",
    "disable_winrm_remote_shell",
    "harden_rdp_nla",
    "disable_rdp_redirection",
    "disable_admin_shares",
    "clear_null_sessions",
    "enable_attachment_manager_scan",
    "disable_recent_docs_history",
    "disable_feedback_notifications",
    "disable_ceip",
    "disable_app_telemetry",
    "disable_wifi_sense",
    "disable_content_delivery",
    "disable_input_personalization",
    "enforce_uac_prompt_behavior",
    "restrict_rpc_clients",
    "enable_safe_dll_search",
    "enable_sehop",
    "disable_remote_desktop_firewall_group",
    "disable_remote_assistance_firewall_group",
    "disable_media_sharing_service",
    "disable_xbox_services",
    "disable_geolocation_service",
    "harden_windows_installer",
}

ALL_FIX_ACTIONS = set(SAFE_FIX_ALL_ACTIONS)


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    command_name: str


@dataclass
class Finding:
    id: str
    title: str
    category: str
    status: str  # pass, fail, warn, info, unsupported
    severity: str  # critical, high, medium, low, info
    summary: str
    evidence: str
    recommendation: str
    fixable: bool = False
    fix_action: Optional[str] = None
    safe_for_fix_all: bool = False
    requires_admin: bool = False
    score_impact: Optional[int] = None

    def to_public(self) -> Dict[str, Any]:
        d = asdict(self)
        if d["score_impact"] is None:
            d["score_impact"] = SEVERITY_IMPACT.get(self.severity, 0) if self.status in {"fail", "warn"} else 0
        return d


class AuditLogger:
    lock = threading.Lock()

    @staticmethod
    def write(event: str, detail: Dict[str, Any]) -> None:
        record = {
            "timestamp_utc": _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "event": event,
            "detail": detail,
        }
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
        with AuditLogger.lock:
            with AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def now_iso() -> str:
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def redact_for_log(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("<redacted>" if "token" in k.lower() else redact_for_log(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_for_log(v) for v in value]
    return value


def run_command(args: List[str], command_name: str, timeout: int = DEFAULT_SCAN_TIMEOUT_SECONDS) -> CommandResult:
    """Run a fixed command safely. User input must never be interpolated into args."""
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            encoding="utf-8",
            errors="replace",
            creationflags=(subprocess.CREATE_NO_WINDOW if is_windows() and hasattr(subprocess, "CREATE_NO_WINDOW") else 0),
        )
        return CommandResult(
            ok=completed.returncode == 0,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
            returncode=completed.returncode,
            command_name=command_name,
        )
    except FileNotFoundError as exc:
        return CommandResult(False, "", f"Command unavailable: {exc}", 127, command_name)
    except subprocess.TimeoutExpired:
        return CommandResult(False, "", f"Command timed out after {timeout} seconds", 124, command_name)
    except Exception as exc:
        return CommandResult(False, "", f"Command failed: {exc}", 1, command_name)


def run_powershell(script: str, command_name: str, timeout: int = DEFAULT_SCAN_TIMEOUT_SECONDS) -> CommandResult:
    """
    Run a static PowerShell script block.
    Security rule: only call this with hard-coded script strings from scan/fix functions.
    """
    executable_candidates = ["powershell.exe", "powershell"] if is_windows() else ["pwsh", "powershell"]
    last_result: Optional[CommandResult] = None
    for exe in executable_candidates:
        result = run_command(
            [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            command_name=command_name,
            timeout=timeout,
        )
        last_result = result
        if result.returncode != 127:
            return result
    return last_result or CommandResult(False, "", "PowerShell unavailable", 127, command_name)


def parse_json(text: str) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # PowerShell occasionally emits warnings before JSON. Try to recover the first JSON object/array.
        match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                return None
        return None


def ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "yes", "enabled", "on", "1"}:
            return True
        if v in {"false", "no", "disabled", "off", "0"}:
            return False
    return None


def registry_get(root: Any, path: str, name: str) -> Tuple[bool, Any, str]:
    if winreg is None:
        return False, None, "Windows registry unavailable"
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, _typ = winreg.QueryValueEx(key, name)
            return True, value, ""
    except FileNotFoundError:
        return False, None, "Registry key/value not found"
    except PermissionError:
        return False, None, "Permission denied reading registry"
    except Exception as exc:
        return False, None, f"Registry read failed: {exc}"


def registry_key_exists(root: Any, path: str) -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ):
            return True
    except Exception:
        return False


def registry_set_dword(root: Any, path: str, name: str, value: int) -> CommandResult:
    """Create/open a registry path and set a DWORD value using Python's winreg API."""
    if not is_windows() or winreg is None:
        return CommandResult(False, "", "Windows registry is unavailable.", 127, f"registry_set_{name}")
    try:
        # CreateKeyEx can create the final subkey path under the supplied root on Windows.
        with winreg.CreateKeyEx(root, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
        return CommandResult(True, f"Set {path}\\{name}={int(value)}", "", 0, f"registry_set_{name}")
    except PermissionError as exc:
        return CommandResult(False, "", f"Permission denied writing registry value {path}\\{name}: {exc}", 5, f"registry_set_{name}")
    except Exception as exc:
        return CommandResult(False, "", f"Registry write failed for {path}\\{name}: {exc}", 1, f"registry_set_{name}")



def registry_set_string(root: Any, path: str, name: str, value: str) -> CommandResult:
    """Create/open a registry path and set a string value using Python's winreg API."""
    if not is_windows() or winreg is None:
        return CommandResult(False, "", "Windows registry is unavailable.", 127, f"registry_set_{name}")
    try:
        with winreg.CreateKeyEx(root, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
        return CommandResult(True, f"Set {path}\\{name}={value}", "", 0, f"registry_set_{name}")
    except PermissionError as exc:
        return CommandResult(False, "", f"Permission denied writing registry value {path}\\{name}: {exc}", 5, f"registry_set_{name}")
    except Exception as exc:
        return CommandResult(False, "", f"Registry write failed for {path}\\{name}: {exc}", 1, f"registry_set_{name}")


def registry_set_multi_string(root: Any, path: str, name: str, value: List[str]) -> CommandResult:
    """Create/open a registry path and set a REG_MULTI_SZ value."""
    if not is_windows() or winreg is None:
        return CommandResult(False, "", "Windows registry is unavailable.", 127, f"registry_set_{name}")
    try:
        with winreg.CreateKeyEx(root, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_MULTI_SZ, list(value))
        return CommandResult(True, f"Set {path}\\{name}={value}", "", 0, f"registry_set_{name}")
    except PermissionError as exc:
        return CommandResult(False, "", f"Permission denied writing registry value {path}\\{name}: {exc}", 5, f"registry_set_{name}")
    except Exception as exc:
        return CommandResult(False, "", f"Registry write failed for {path}\\{name}: {exc}", 1, f"registry_set_{name}")


def registry_delete_value(root: Any, path: str, name: str) -> CommandResult:
    """Delete a registry value if present. Missing values are treated as success."""
    if not is_windows() or winreg is None:
        return CommandResult(False, "", "Windows registry is unavailable.", 127, f"registry_delete_{name}")
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, name)
                return CommandResult(True, f"Deleted {path}\\{name}", "", 0, f"registry_delete_{name}")
            except FileNotFoundError:
                return CommandResult(True, f"{path}\\{name} was not present", "", 0, f"registry_delete_{name}")
    except FileNotFoundError:
        return CommandResult(True, f"{path} was not present", "", 0, f"registry_delete_{name}")
    except PermissionError as exc:
        return CommandResult(False, "", f"Permission denied deleting registry value {path}\\{name}: {exc}", 5, f"registry_delete_{name}")
    except Exception as exc:
        return CommandResult(False, "", f"Registry delete failed for {path}\\{name}: {exc}", 1, f"registry_delete_{name}")


def combine_results(command_name: str, results: List[CommandResult]) -> CommandResult:
    ok = all(r.ok for r in results)
    stdout = "\n".join(r.stdout for r in results if r.stdout).strip()
    stderr = "\n".join(r.stderr for r in results if r.stderr).strip()
    returncode = 0 if ok else next((r.returncode for r in results if not r.ok), 1)
    return CommandResult(ok, stdout, stderr, returncode, command_name)


def compact_error(text: str, limit: int = 360) -> str:
    cleaned = re.sub(r"\s+", " ", text or "").strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3].rstrip() + "..."


def windows_build() -> Dict[str, Any]:
    info = {
        "platform": platform.platform(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version.split()[0],
        "is_admin": is_admin(),
        "app_version": APP_VERSION,
    }
    if is_windows() and winreg:
        root = winreg.HKEY_LOCAL_MACHINE
        path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        for reg_name, key_name in [
            ("ProductName", "product_name"),
            ("DisplayVersion", "display_version"),
            ("CurrentBuild", "current_build"),
            ("UBR", "ubr"),
            ("ReleaseId", "release_id"),
            ("InstallDate", "install_date_epoch"),
        ]:
            ok, value, _ = registry_get(root, path, reg_name)
            if ok:
                info[key_name] = value
    return info


def make_finding(
    id: str,
    title: str,
    category: str,
    status: str,
    severity: str,
    summary: str,
    evidence: str,
    recommendation: str,
    fixable: bool = False,
    fix_action: Optional[str] = None,
    safe_for_fix_all: bool = False,
    requires_admin: bool = False,
    score_impact: Optional[int] = None,
) -> Finding:
    if fixable and fix_action not in ALL_FIX_ACTIONS:
        # Fail closed. A typo should not expose an unexpected action.
        fixable = False
        fix_action = None
        safe_for_fix_all = False
    if safe_for_fix_all and fix_action not in SAFE_FIX_ALL_ACTIONS:
        safe_for_fix_all = False
    return Finding(
        id=id,
        title=title,
        category=category,
        status=status,
        severity=severity,
        summary=summary,
        evidence=evidence,
        recommendation=recommendation,
        fixable=fixable,
        fix_action=fix_action,
        safe_for_fix_all=safe_for_fix_all,
        requires_admin=requires_admin,
        score_impact=score_impact,
    )


def unsupported(id: str, title: str, category: str, evidence: str) -> Finding:
    return make_finding(
        id=id,
        title=title,
        category=category,
        status="unsupported",
        severity="info",
        summary="This check could not be completed on this computer.",
        evidence=evidence,
        recommendation="Review manually or run the dashboard on a supported Windows system with appropriate permissions.",
    )


def check_firewall() -> List[Finding]:
    """Assess Windows Firewall profile posture and common rule groups."""
    findings: List[Finding] = []
    ps = r"""
    $profiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
    $profiles | ConvertTo-Json -Depth 4 -Compress
    """
    result = run_powershell(ps, "firewall_profiles")
    if not result.ok:
        return [unsupported("firewall_profiles", "Windows Firewall profiles", "Network Protection", result.stderr or result.stdout)]
    profiles = ensure_list(parse_json(result.stdout))
    if not profiles:
        return [unsupported("firewall_profiles", "Windows Firewall profiles", "Network Protection", "No firewall profile data returned.")]

    disabled = [p.get("Name", "Unknown") for p in profiles if normalize_bool(p.get("Enabled")) is False]
    non_blocking = [p.get("Name", "Unknown") for p in profiles if str(p.get("DefaultInboundAction", "")).lower() not in {"0", "block"}]
    evidence = "; ".join(f"{p.get('Name')}: Enabled={p.get('Enabled')}, Inbound={p.get('DefaultInboundAction')}, Outbound={p.get('DefaultOutboundAction')}" for p in profiles)

    if disabled:
        findings.append(make_finding(
            "firewall_profiles",
            "Windows Firewall is disabled on one or more profiles",
            "Network Protection",
            "fail",
            "critical",
            f"Firewall protection is disabled for: {', '.join(disabled)}.",
            evidence,
            "Enable Windows Firewall for Domain, Private, and Public profiles.",
            True,
            "enable_firewall",
            True,
            True,
        ))
    else:
        findings.append(make_finding(
            "firewall_profiles",
            "Windows Firewall profiles enabled",
            "Network Protection",
            "pass",
            "info",
            "All Windows Firewall profiles appear enabled.",
            evidence,
            "No action needed.",
        ))

    if non_blocking:
        findings.append(make_finding(
            "firewall_default_inbound",
            "Firewall default inbound policy allows traffic",
            "Network Protection",
            "warn",
            "high",
            f"One or more firewall profiles do not default-block inbound traffic: {', '.join(non_blocking)}.",
            evidence,
            "Set Domain, Private, and Public profiles to block unsolicited inbound traffic by default.",
            True,
            "harden_firewall_default_inbound",
            True,
            True,
            10,
        ))
    else:
        findings.append(make_finding(
            "firewall_default_inbound",
            "Firewall default inbound policy blocks traffic",
            "Network Protection",
            "pass",
            "info",
            "All firewall profiles appear configured to block unsolicited inbound traffic by default.",
            evidence,
            "No action needed.",
        ))

    # Rule group checks are actionable and free. These are conservative hardening controls for personal PCs.
    for group_name, finding_id, title, action in [
        ("Network Discovery", "network_discovery_rules", "Network Discovery firewall rules are enabled", "disable_network_discovery_firewall_group"),
        ("File and Printer Sharing", "file_printer_sharing_rules", "File and Printer Sharing firewall rules are enabled", "disable_file_printer_sharing_firewall_group"),
    ]:
        ps_group = f"""
        $rules = @(Get-NetFirewallRule -DisplayGroup '{group_name}' -ErrorAction SilentlyContinue | Where-Object {{ $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' }})
        [pscustomobject]@{{ Count=$rules.Count; Names=@($rules | Select-Object -First 12 -ExpandProperty DisplayName) }} | ConvertTo-Json -Depth 5 -Compress
        """
        res = run_powershell(ps_group, finding_id, timeout=15)
        data = parse_json(res.stdout) if res.ok else None
        if data and int(data.get("Count") or 0) > 0:
            findings.append(make_finding(
                finding_id,
                title,
                "Network Protection",
                "warn",
                "medium",
                f"{int(data.get('Count'))} inbound rule(s) are enabled in the {group_name} group.",
                json.dumps(data, ensure_ascii=False),
                f"Disable inbound {group_name} firewall rules unless this PC intentionally shares resources on a trusted LAN.",
                True,
                action,
                True,
                True,
                6,
            ))
        elif data:
            findings.append(make_finding(
                finding_id,
                f"{group_name} inbound firewall rules are not enabled",
                "Network Protection",
                "pass",
                "info",
                f"No enabled inbound firewall rules were found in the {group_name} group.",
                json.dumps(data, ensure_ascii=False),
                "No action needed.",
            ))
        else:
            findings.append(unsupported(finding_id, f"{group_name} firewall rule group", "Network Protection", res.stderr or res.stdout))

    return findings

def check_defender() -> List[Finding]:
    findings: List[Finding] = []
    ps_status = r"""
    $status = Get-MpComputerStatus -ErrorAction Stop | Select-Object `
      AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,QuickScanAge,FullScanAge
    $status | ConvertTo-Json -Depth 4 -Compress
    """
    status_result = run_powershell(ps_status, "defender_status")
    status = parse_json(status_result.stdout) if status_result.ok else None
    if not status:
        findings.append(unsupported("defender_status", "Microsoft Defender status", "Endpoint Protection", status_result.stderr or status_result.stdout))
        return findings

    av_enabled = normalize_bool(status.get("AntivirusEnabled"))
    service_enabled = normalize_bool(status.get("AMServiceEnabled"))
    realtime = normalize_bool(status.get("RealTimeProtectionEnabled"))
    behavior = normalize_bool(status.get("BehaviorMonitorEnabled"))
    ioav = normalize_bool(status.get("IoavProtectionEnabled"))
    sig_last = status.get("AntivirusSignatureLastUpdated")
    evidence = ", ".join([
        f"AMServiceEnabled={status.get('AMServiceEnabled')}",
        f"AntivirusEnabled={status.get('AntivirusEnabled')}",
        f"RealTimeProtectionEnabled={status.get('RealTimeProtectionEnabled')}",
        f"BehaviorMonitorEnabled={status.get('BehaviorMonitorEnabled')}",
        f"IoavProtectionEnabled={status.get('IoavProtectionEnabled')}",
        f"SignatureLastUpdated={sig_last}",
        f"TamperProtected={status.get('IsTamperProtected')}",
    ])

    if av_enabled is False or service_enabled is False:
        findings.append(make_finding(
            "defender_antivirus",
            "Microsoft Defender antivirus is not fully enabled",
            "Endpoint Protection",
            "fail",
            "critical",
            "Microsoft Defender antivirus service or antivirus protection appears disabled.",
            evidence,
            "Enable Microsoft Defender or verify another enterprise antivirus is installed and active.",
            False,
        ))
    else:
        findings.append(make_finding(
            "defender_antivirus",
            "Antivirus protection is enabled",
            "Endpoint Protection",
            "pass",
            "info",
            "Microsoft Defender antivirus appears enabled.",
            evidence,
            "No action needed.",
        ))

    if realtime is False or behavior is False or ioav is False:
        findings.append(make_finding(
            "defender_realtime",
            "Defender real-time protection is incomplete",
            "Endpoint Protection",
            "fail",
            "critical",
            "One or more real-time Defender protections are disabled.",
            evidence,
            "Enable real-time, behavior, and file/download scanning protection.",
            True,
            "enable_defender_realtime",
            True,
            True,
        ))
    else:
        findings.append(make_finding(
            "defender_realtime",
            "Real-time malware protection enabled",
            "Endpoint Protection",
            "pass",
            "info",
            "Defender real-time protection appears active.",
            evidence,
            "No action needed.",
        ))

    # Signature recency check. Defender returns DateTime text that can vary by locale, so ask PS for age in days separately.
    ps_sig_age = r"""
    $s = Get-MpComputerStatus -ErrorAction Stop
    $age = if ($s.AntivirusSignatureLastUpdated) { [int]((Get-Date) - $s.AntivirusSignatureLastUpdated).TotalDays } else { $null }
    [pscustomobject]@{ SignatureAgeDays=$age; Version=$s.AntivirusSignatureVersion } | ConvertTo-Json -Compress
    """
    sig_result = run_powershell(ps_sig_age, "defender_signature_age")
    sig = parse_json(sig_result.stdout) if sig_result.ok else None
    if sig and sig.get("SignatureAgeDays") is not None:
        age = int(sig.get("SignatureAgeDays"))
        if age > 7:
            findings.append(make_finding(
                "defender_signatures",
                "Defender signatures are stale",
                "Endpoint Protection",
                "warn",
                "medium",
                f"Defender signatures appear {age} days old.",
                f"SignatureAgeDays={age}; Version={sig.get('Version')}",
                "Update Defender security intelligence.",
                True,
                "update_defender_signatures",
                True,
                True,
            ))
        else:
            findings.append(make_finding(
                "defender_signatures",
                "Defender signatures are recent",
                "Endpoint Protection",
                "pass",
                "info",
                f"Defender signatures appear current within {age} day(s).",
                f"SignatureAgeDays={age}; Version={sig.get('Version')}",
                "No action needed.",
            ))


    # Quick scan recency. This is low-risk and free to remediate by starting a Defender quick scan.
    try:
        quick_age_raw = status.get("QuickScanAge")
        quick_age = int(quick_age_raw) if quick_age_raw is not None else None
    except Exception:
        quick_age = None
    if quick_age is not None:
        if quick_age > 14:
            findings.append(make_finding(
                "defender_quick_scan_recency",
                "Defender quick scan is stale",
                "Endpoint Protection",
                "warn",
                "low",
                f"Defender has not completed a quick scan in {quick_age} day(s).",
                f"QuickScanAge={quick_age}",
                "Run a Microsoft Defender quick scan.",
                True,
                "run_defender_quick_scan",
                True,
                True,
                4,
            ))
        else:
            findings.append(make_finding(
                "defender_quick_scan_recency",
                "Defender quick scan recency is acceptable",
                "Endpoint Protection",
                "pass",
                "info",
                f"Defender quick scan age is {quick_age} day(s).",
                f"QuickScanAge={quick_age}",
                "No action needed.",
            ))

    ps_pref = r"""
    $p = Get-MpPreference -ErrorAction Stop | Select-Object MAPSReporting,SubmitSamplesConsent,PUAProtection,EnableControlledFolderAccess,ExclusionPath,ExclusionProcess,ExclusionExtension,DisableRealtimeMonitoring
    $p | ConvertTo-Json -Depth 5 -Compress
    """
    pref_result = run_powershell(ps_pref, "defender_preferences")
    pref = parse_json(pref_result.stdout) if pref_result.ok else None
    if pref:
        maps = str(pref.get("MAPSReporting"))
        sample = str(pref.get("SubmitSamplesConsent"))
        cloud_ok = maps.lower() not in {"0", "disabled", "never", "none"}
        if not cloud_ok:
            findings.append(make_finding(
                "defender_cloud",
                "Defender cloud protection appears disabled",
                "Endpoint Protection",
                "warn",
                "medium",
                "Cloud-based protection improves detection of new and emerging threats.",
                f"MAPSReporting={maps}; SubmitSamplesConsent={sample}",
                "Enable Defender cloud-delivered protection and safe sample submission settings.",
                True,
                "enable_defender_cloud",
                True,
                True,
            ))
        else:
            findings.append(make_finding(
                "defender_cloud",
                "Defender cloud protection configured",
                "Endpoint Protection",
                "pass",
                "info",
                "Defender cloud-based protection appears configured.",
                f"MAPSReporting={maps}; SubmitSamplesConsent={sample}",
                "No action needed.",
            ))

        pua = str(pref.get("PUAProtection"))
        if pua.lower() in {"0", "disabled", "off"}:
            findings.append(make_finding(
                "defender_pua",
                "Potentially unwanted app protection is disabled",
                "Endpoint Protection",
                "warn",
                "low",
                "PUA protection can block adware, bundlers, and low-reputation applications.",
                f"PUAProtection={pua}",
                "Enable Microsoft Defender PUA protection.",
                True,
                "enable_defender_pua",
                True,
                True,
            ))
        else:
            findings.append(make_finding(
                "defender_pua",
                "PUA protection is enabled or managed",
                "Endpoint Protection",
                "pass",
                "info",
                "Defender PUA protection does not appear disabled.",
                f"PUAProtection={pua}",
                "No action needed.",
            ))


        cfa = str(pref.get("EnableControlledFolderAccess"))
        if cfa.lower() in {"0", "disabled", "off", "auditmode", "none"}:
            findings.append(make_finding(
                "controlled_folder_access",
                "Controlled Folder Access is not enabled",
                "Endpoint Protection",
                "warn",
                "low",
                "Controlled Folder Access can reduce ransomware impact by restricting unauthorized file changes in protected folders.",
                f"EnableControlledFolderAccess={cfa}",
                "Enable Microsoft Defender Controlled Folder Access. If a trusted app is blocked later, add that app through Windows Security.",
                True,
                "enable_controlled_folder_access",
                True,
                True,
                4,
            ))
        else:
            findings.append(make_finding(
                "controlled_folder_access",
                "Controlled Folder Access is enabled or managed",
                "Endpoint Protection",
                "pass",
                "info",
                "Controlled Folder Access does not appear disabled.",
                f"EnableControlledFolderAccess={cfa}",
                "No action needed.",
            ))

        exclusions = []
        for key in ["ExclusionPath", "ExclusionProcess", "ExclusionExtension"]:
            val = pref.get(key)
            if isinstance(val, list):
                exclusions.extend([f"{key}:{x}" for x in val if x])
            elif val:
                exclusions.append(f"{key}:{val}")
        if exclusions:
            findings.append(make_finding(
                "defender_exclusions",
                "Defender exclusions are configured",
                "Endpoint Protection",
                "warn",
                "medium",
                "Defender exclusions can be legitimate, but they also create blind spots if unnecessary or overly broad.",
                f"Configured exclusions: {len(exclusions)}; " + "; ".join(exclusions[:20]),
                "Remove all Defender exclusions unless they are required for a trusted business application or development tool.",
                True,
                "remove_all_defender_exclusions",
                True,
                True,
                6,
            ))
        else:
            findings.append(make_finding(
                "defender_exclusions",
                "No Defender exclusions found",
                "Endpoint Protection",
                "pass",
                "info",
                "No Microsoft Defender exclusions were returned by Get-MpPreference.",
                "ExclusionPath/Process/Extension empty.",
                "No action needed.",
            ))

    # Defender Network Protection and Attack Surface Reduction baseline. These are free Microsoft Defender controls.
    ps_advanced = r"""
    try {
      $p = Get-MpPreference -ErrorAction Stop
      [pscustomobject]@{
        EnableNetworkProtection=$p.EnableNetworkProtection
        AttackSurfaceReductionRules_Ids=$p.AttackSurfaceReductionRules_Ids
        AttackSurfaceReductionRules_Actions=$p.AttackSurfaceReductionRules_Actions
      } | ConvertTo-Json -Depth 6 -Compress
    } catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    advanced_result = run_powershell(ps_advanced, "defender_advanced_preferences")
    advanced = parse_json(advanced_result.stdout) if advanced_result.ok else None
    if advanced and not advanced.get("Error"):
        netprot = str(advanced.get("EnableNetworkProtection"))
        if netprot.lower() in {"0", "disabled", "off", "none"}:
            findings.append(make_finding(
                "defender_network_protection",
                "Defender Network Protection is disabled",
                "Endpoint Protection",
                "warn",
                "medium",
                "Network Protection helps block outbound connections to known malicious hosts and phishing infrastructure.",
                f"EnableNetworkProtection={netprot}",
                "Enable Microsoft Defender Network Protection.",
                True,
                "enable_defender_network_protection",
                True,
                True,
                6,
            ))
        else:
            findings.append(make_finding(
                "defender_network_protection",
                "Defender Network Protection is enabled or managed",
                "Endpoint Protection",
                "pass",
                "info",
                "Defender Network Protection does not appear disabled.",
                f"EnableNetworkProtection={netprot}",
                "No action needed.",
            ))

        baseline_ids = [
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
            "3B576869-A4EC-4529-8536-B80A7769E899",
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
            "C1DB55AB-C21A-4637-BB3F-A12568109D35",
        ]
        ids = [str(x).upper() for x in ensure_list(advanced.get("AttackSurfaceReductionRules_Ids")) if str(x).strip()]
        actions = ensure_list(advanced.get("AttackSurfaceReductionRules_Actions"))
        enabled_ids = set()
        for idx, rule_id in enumerate(ids):
            action_value = str(actions[idx]) if idx < len(actions) else ""
            if action_value in {"1", "Enabled", "Block"}:
                enabled_ids.add(rule_id)
        missing = [rule_id for rule_id in baseline_ids if rule_id not in enabled_ids]
        if missing:
            findings.append(make_finding(
                "defender_asr_baseline",
                "Defender Attack Surface Reduction baseline is incomplete",
                "Endpoint Protection",
                "warn",
                "medium",
                f"{len(missing)} high-value Microsoft Defender ASR rule(s) are not enabled in block mode.",
                "Missing baseline rule IDs: " + ", ".join(missing),
                "Enable a conservative Defender ASR baseline for Office child-process abuse, executable content, LSASS credential theft, ransomware behavior, and email/web content abuse.",
                True,
                "enable_defender_asr_baseline",
                True,
                True,
                6,
            ))
        else:
            findings.append(make_finding(
                "defender_asr_baseline",
                "Defender Attack Surface Reduction baseline is enabled",
                "Endpoint Protection",
                "pass",
                "info",
                "The selected high-value ASR baseline rules appear enabled in block mode.",
                "Enabled baseline rule IDs: " + ", ".join(sorted(enabled_ids.intersection(set(baseline_ids)))),
                "No action needed.",
            ))
    else:
        findings.append(unsupported("defender_advanced_preferences", "Defender advanced preferences", "Endpoint Protection", str(advanced.get("Error") if advanced else advanced_result.stderr or advanced_result.stdout)))

    return findings


def check_installed_antivirus() -> List[Finding]:
    ps = r"""
    $products = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
      Select-Object displayName,productState,pathToSignedProductExe
    $products | ConvertTo-Json -Depth 4 -Compress
    """
    result = run_powershell(ps, "installed_antivirus")
    if not result.ok:
        return [unsupported("installed_antivirus", "Registered antivirus products", "Endpoint Protection", result.stderr or result.stdout)]
    products = ensure_list(parse_json(result.stdout))
    names = [str(p.get("displayName", "Unknown")) for p in products if isinstance(p, dict)]
    if names:
        return [make_finding(
            "installed_antivirus",
            "Antivirus product registered with Windows Security Center",
            "Endpoint Protection",
            "pass",
            "info",
            f"Registered antivirus product(s): {', '.join(names)}.",
            json.dumps(products, ensure_ascii=False)[:800],
            "No action needed. Verify the product is active if using a third-party AV.",
        )]
    return [make_finding(
        "installed_antivirus",
        "No antivirus product reported by Windows Security Center",
        "Endpoint Protection",
        "warn",
        "high",
        "Windows Security Center did not report an antivirus product.",
        result.stdout or "No products returned.",
        "Enable Microsoft Defender or install a trusted antivirus product.",
    )]


def check_windows_update() -> List[Finding]:
    findings: List[Finding] = []
    ps = r"""
    $hotfix = Get-HotFix -ErrorAction SilentlyContinue |
      Where-Object { $_.InstalledOn } |
      Sort-Object InstalledOn -Descending |
      Select-Object -First 1 @{n='HotFixID';e={$_.HotFixID}}, @{n='InstalledOn';e={$_.InstalledOn.ToString('yyyy-MM-dd')}}
    if ($hotfix) { $hotfix | ConvertTo-Json -Compress } else { '{}' }
    """
    result = run_powershell(ps, "last_hotfix")
    hotfix = parse_json(result.stdout) if result.ok else None
    if hotfix and hotfix.get("InstalledOn"):
        date_text = hotfix.get("InstalledOn")
        try:
            installed_date = _dt.datetime.strptime(date_text, "%Y-%m-%d").date()
            age = (_dt.date.today() - installed_date).days
            if age > 45:
                findings.append(make_finding(
                    "windows_update_recency",
                    "No recent Windows hotfix found",
                    "Patch Management",
                    "warn",
                    "high" if age > 90 else "medium",
                    f"The most recent installed hotfix found is {age} days old.",
                    f"HotFixID={hotfix.get('HotFixID')}; InstalledOn={date_text}",
                    "Start a Windows Update scan. The update service may still require a reboot after installation.",
                    True,
                    "run_windows_update_scan",
                    True,
                    True,
                ))
            else:
                findings.append(make_finding(
                    "windows_update_recency",
                    "Recent Windows hotfix found",
                    "Patch Management",
                    "pass",
                    "info",
                    f"A Windows hotfix was found within the last {age} day(s).",
                    f"HotFixID={hotfix.get('HotFixID')}; InstalledOn={date_text}",
                    "No action needed unless Windows Update shows pending updates.",
                ))
        except Exception:
            findings.append(unsupported("windows_update_recency", "Windows hotfix recency", "Patch Management", f"Unable to parse date: {date_text}"))
    else:
        findings.append(unsupported("windows_update_recency", "Windows hotfix recency", "Patch Management", result.stderr or result.stdout or "No hotfix data returned."))

    pending_paths = []
    if is_windows() and winreg:
        checks = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager"),
        ]
        for root, path in checks[:2]:
            if registry_key_exists(root, path):
                pending_paths.append(path)
        ok, value, _ = registry_get(winreg.HKEY_LOCAL_MACHINE, checks[2][1], "PendingFileRenameOperations")
        if ok and value:
            pending_paths.append(r"SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations")
    if pending_paths:
        findings.append(make_finding(
            "pending_reboot",
            "Pending reboot detected",
            "Patch Management",
            "warn",
            "medium",
            "Windows has pending reboot indicators. Some updates or security changes may not be fully applied until restart.",
            "; ".join(pending_paths),
            "Save work. The dashboard can schedule a restart in 60 seconds to complete pending update/security changes.",
            True,
            "schedule_restart_60",
            True,
            True,
            6,
        ))
    else:
        findings.append(make_finding(
            "pending_reboot",
            "No common pending reboot indicators found",
            "Patch Management",
            "pass",
            "info",
            "Common pending reboot registry indicators were not found.",
            "Checked Windows Update, Component Based Servicing, and Session Manager indicators.",
            "No action needed.",
        ))
    return findings



def windows_product_name() -> str:
    info = windows_build()
    return str(info.get("product_name") or "")


def is_home_edition() -> bool:
    name = windows_product_name().lower()
    return "home" in name and not any(x in name for x in ["pro", "enterprise", "education", "server"])


def firewall_profiles_are_protective() -> bool:
    """Return True if Windows Firewall profiles are enabled and not default-allowing inbound traffic.

    Windows builds serialize DefaultInboundAction inconsistently through PowerShell/JSON
    (for example 0/Block/NotConfigured). For this dashboard, the unsafe state is an
    explicit Allow value or a disabled profile. Anything else is treated as protective
    when the profile is enabled because Windows Defender Firewall blocks unsolicited
    inbound traffic by default on normal client configurations.
    """
    ps = r"""
    try {
      $profiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction
      $bad = @($profiles | Where-Object {
        (-not $_.Enabled) -or ([string]$_.DefaultInboundAction -match 'Allow')
      })
      [pscustomobject]@{ Protective=($bad.Count -eq 0); Profiles=$profiles } | ConvertTo-Json -Depth 5 -Compress
    } catch { [pscustomobject]@{ Protective=$false; Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    res = run_powershell(ps, "firewall_protective_check", timeout=10)
    data = parse_json(res.stdout) if res.ok else None
    return bool(data and data.get("Protective") is True)


def risky_port_block_rule_exists() -> bool:
    """Return True when dashboard-created inbound block rule(s) exist and are enabled."""
    ps = r"""
    try {
      $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'CyberDashboard - Block risky inbound TCP services*' -and $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' })
      $ports = @()
      foreach($r in $rules){
        try {
          $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
          $ports += @($pf.LocalPort)
        } catch {}
      }
      [pscustomobject]@{ Exists = ($rules.Count -gt 0); RuleCount=$rules.Count; Ports=$ports } | ConvertTo-Json -Depth 5 -Compress
    } catch { [pscustomobject]@{ Exists=$false; Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    res = run_powershell(ps, "risky_port_block_rule_exists", timeout=10)
    data = parse_json(res.stdout) if res.ok else None
    return bool(data and data.get("Exists") is True)


def check_bitlocker_secureboot_tpm() -> List[Finding]:
    findings: List[Finding] = []
    ps_bitlocker = r"""
    $drive = $env:SystemDrive
    $vol = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,LockStatus
    $vol | ConvertTo-Json -Depth 4 -Compress
    """
    result = run_powershell(ps_bitlocker, "bitlocker_status")
    bit = parse_json(result.stdout) if result.ok else None
    if bit:
        protection = str(bit.get("ProtectionStatus"))
        volume_status = str(bit.get("VolumeStatus"))
        enabled = protection.lower() in {"on", "1"} or "fullyencrypted" in volume_status.lower()
        if enabled:
            findings.append(make_finding(
                "bitlocker_system_drive",
                "System drive encryption appears protected",
                "Device Hardening",
                "pass",
                "info",
                "BitLocker reports protection on or system volume encrypted.",
                f"ProtectionStatus={protection}; VolumeStatus={volume_status}; EncryptionPercentage={bit.get('EncryptionPercentage')}",
                "No action needed. Verify recovery key backup is stored safely.",
            ))
        else:
            if is_home_edition():
                findings.append(make_finding(
                    "drive_encryption_builtin_availability",
                    "Free built-in system-drive encryption is not available on this Windows edition",
                    "Device Hardening",
                    "info",
                    "info",
                    "This PC appears to be running a Home edition. BitLocker system-drive encryption is not treated as a required fix because Windows is offering it as a paid edition upgrade on this machine.",
                    f"ProductName={windows_product_name()}; ProtectionStatus={protection}; VolumeStatus={volume_status}; EncryptionPercentage={bit.get('EncryptionPercentage')}",
                    "No paid upgrade is recommended by this dashboard. Use free compensating controls: strong Windows sign-in, Secure Boot, TPM, Defender, and regular backups.",
                    False,
                ))
            else:
                findings.append(make_finding(
                    "bitlocker_system_drive",
                    "System drive encryption is not fully protected",
                    "Device Hardening",
                    "fail",
                    "high",
                    "The system drive does not appear fully protected by BitLocker.",
                    f"ProtectionStatus={protection}; VolumeStatus={volume_status}; EncryptionPercentage={bit.get('EncryptionPercentage')}",
                    "Enable BitLocker using the free built-in Windows feature. The dashboard creates a recovery-key file under Documents\\CyberDashboard-RecoveryKeys before enabling used-space-only encryption.",
                    True,
                    "enable_bitlocker_safely",
                    True,
                    True,
                    16,
                ))
    else:
        findings.append(unsupported("bitlocker_system_drive", "BitLocker system drive status", "Device Hardening", result.stderr or result.stdout))

    ps_secureboot = r"""
    try {
      [pscustomobject]@{ Supported=$true; Enabled=(Confirm-SecureBootUEFI -ErrorAction Stop) } | ConvertTo-Json -Compress
    } catch {
      [pscustomobject]@{ Supported=$false; Error=$_.Exception.Message } | ConvertTo-Json -Compress
    }
    """
    sb_result = run_powershell(ps_secureboot, "secure_boot")
    sb = parse_json(sb_result.stdout) if sb_result.ok else None
    if sb and sb.get("Supported") is False:
        findings.append(unsupported("secure_boot", "Secure Boot", "Device Hardening", str(sb.get("Error", "Secure Boot unsupported or unavailable."))))
    elif sb:
        enabled = normalize_bool(sb.get("Enabled"))
        if enabled:
            findings.append(make_finding("secure_boot", "Secure Boot is enabled", "Device Hardening", "pass", "info", "Secure Boot appears enabled.", f"Enabled={sb.get('Enabled')}", "No action needed."))
        else:
            findings.append(make_finding("secure_boot", "Secure Boot is disabled at firmware level", "Device Hardening", "info", "info", "Secure Boot helps prevent boot-level malware, but it must be changed in UEFI/BIOS firmware and cannot be safely auto-fixed from this dashboard.", f"Enabled={sb.get('Enabled')}", "No paid fix is recommended. Enable Secure Boot manually in firmware settings if supported.", False))
    else:
        findings.append(unsupported("secure_boot", "Secure Boot", "Device Hardening", sb_result.stderr or sb_result.stdout))

    ps_tpm = r"""
    try { Get-Tpm -ErrorAction Stop | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated | ConvertTo-Json -Compress }
    catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    tpm_result = run_powershell(ps_tpm, "tpm_status")
    tpm = parse_json(tpm_result.stdout) if tpm_result.ok else None
    if tpm and not tpm.get("Error"):
        ready = normalize_bool(tpm.get("TpmReady"))
        present = normalize_bool(tpm.get("TpmPresent"))
        if present and ready:
            findings.append(make_finding("tpm_status", "TPM is present and ready", "Device Hardening", "pass", "info", "TPM appears present and ready.", json.dumps(tpm), "No action needed."))
        else:
            findings.append(make_finding("tpm_status", "TPM is not ready or not available", "Device Hardening", "info", "info", "TPM is not present or not ready. This is hardware/firmware dependent and is not treated as an automatic software fix.", json.dumps(tpm), "No paid fix is recommended. Review firmware TPM settings only if the device supports it.", False))
    else:
        findings.append(unsupported("tpm_status", "TPM status", "Device Hardening", str(tpm.get("Error") if tpm else tpm_result.stderr or tpm_result.stdout)))
    return findings


def check_remote_access() -> List[Finding]:
    findings: List[Finding] = []
    if is_windows() and winreg:
        ok, deny, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
        if ok:
            if int(deny) == 0:
                findings.append(make_finding(
                    "rdp_enabled",
                    "Remote Desktop is enabled",
                    "Remote Access",
                    "fail",
                    "high",
                    "RDP is enabled. This increases exposure if not strictly needed, especially on laptops or unmanaged PCs.",
                    "HKLM...Terminal Server fDenyTSConnections=0",
                    "Disable RDP unless it is required and protected by VPN, MFA, and firewall restrictions.",
                    True,
                    "disable_rdp",
                    True,
                    True,
                ))
            else:
                findings.append(make_finding("rdp_enabled", "Remote Desktop is disabled", "Remote Access", "pass", "info", "RDP is not enabled through the standard Terminal Server setting.", f"fDenyTSConnections={deny}", "No action needed."))
        else:
            findings.append(unsupported("rdp_enabled", "Remote Desktop setting", "Remote Access", msg))

        ok, ra, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp")
        if ok and int(ra) == 1:
            findings.append(make_finding("remote_assistance", "Remote Assistance is enabled", "Remote Access", "warn", "medium", "Remote Assistance allows remote support invitations and should be disabled if not used.", "fAllowToGetHelp=1", "Disable Remote Assistance if not required.", True, "disable_remote_assistance", True, True))
        elif ok:
            findings.append(make_finding("remote_assistance", "Remote Assistance is disabled", "Remote Access", "pass", "info", "Remote Assistance appears disabled.", f"fAllowToGetHelp={ra}", "No action needed."))
        else:
            findings.append(unsupported("remote_assistance", "Remote Assistance setting", "Remote Access", msg))
    else:
        findings.append(unsupported("rdp_enabled", "Remote Desktop setting", "Remote Access", "Windows registry unavailable."))
        findings.append(unsupported("remote_assistance", "Remote Assistance setting", "Remote Access", "Windows registry unavailable."))

    ps_winrm = r"""
    $svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($svc) { $svc | Select-Object Name,Status,StartType | ConvertTo-Json -Compress } else { [pscustomobject]@{Missing=$true} | ConvertTo-Json -Compress }
    """
    result = run_powershell(ps_winrm, "winrm_service")
    svc = parse_json(result.stdout) if result.ok else None
    if svc and not svc.get("Missing"):
        status = str(svc.get("Status"))
        start = str(svc.get("StartType"))
        if status.lower() == "running" or start.lower() in {"automatic", "automaticdelayedstart"}:
            findings.append(make_finding("winrm_service", "WinRM is enabled or running", "Remote Access", "warn", "medium", "WinRM enables remote PowerShell management. It should be disabled unless intentionally managed.", f"Status={status}; StartType={start}", "Disable WinRM if this PC is not remotely managed.", True, "disable_winrm", True, True))
        else:
            findings.append(make_finding("winrm_service", "WinRM is not running", "Remote Access", "pass", "info", "WinRM is not running and does not appear automatically started.", f"Status={status}; StartType={start}", "No action needed."))
    else:
        findings.append(unsupported("winrm_service", "WinRM service", "Remote Access", result.stderr or result.stdout))
    return findings


def check_legacy_protocols_services() -> List[Finding]:
    findings: List[Finding] = []
    ps_smb = r"""
    try {
      $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop | Select-Object FeatureName,State
      $feature | ConvertTo-Json -Compress
    } catch {
      [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress
    }
    """
    result = run_powershell(ps_smb, "smb1_status")
    smb = parse_json(result.stdout) if result.ok else None
    if smb and not smb.get("Error"):
        state = str(smb.get("State"))
        if state.lower() == "enabled":
            findings.append(make_finding("smb1_status", "SMBv1 is enabled", "Network Protection", "fail", "critical", "SMBv1 is a legacy file-sharing protocol with well-known security risks.", f"State={state}", "Disable SMBv1 unless required for a specific legacy dependency.", True, "disable_smb1", True, True))
        else:
            findings.append(make_finding("smb1_status", "SMBv1 is disabled", "Network Protection", "pass", "info", "SMBv1 does not appear enabled.", f"State={state}", "No action needed."))
    else:
        findings.append(unsupported("smb1_status", "SMBv1 optional feature", "Network Protection", str(smb.get("Error") if smb else result.stderr or result.stdout)))

    high_risk_services = [
        ("RemoteRegistry", "Remote Registry"),
        ("TlntSvr", "Telnet Server"),
        ("FTPSVC", "Microsoft FTP Service"),
        ("SNMP", "SNMP Service"),
    ]
    for svc_name, display in high_risk_services:
        ps = f"""
        $svc = Get-Service -Name '{svc_name}' -ErrorAction SilentlyContinue
        if ($svc) {{ $svc | Select-Object Name,Status,StartType | ConvertTo-Json -Compress }} else {{ [pscustomobject]@{{Missing=$true}} | ConvertTo-Json -Compress }}
        """
        res = run_powershell(ps, f"service_{svc_name}")
        svc = parse_json(res.stdout) if res.ok else None
        if not svc or svc.get("Missing"):
            findings.append(make_finding(f"service_{svc_name.lower()}", f"{display} not installed or not found", "Network Protection", "pass", "info", f"{display} was not found as an installed service.", res.stdout or "Missing=True", "No action needed."))
            continue
        status = str(svc.get("Status"))
        start = str(svc.get("StartType"))
        risky = status.lower() == "running" or start.lower() in {"automatic", "automaticdelayedstart"}
        if risky:
            action_map = {
                "RemoteRegistry": "disable_remote_registry",
                "TlntSvr": "disable_telnet_service",
                "FTPSVC": "disable_ftp_service",
                "SNMP": "disable_snmp_service",
            }
            findings.append(make_finding(
                f"service_{svc_name.lower()}",
                f"{display} is enabled or running",
                "Network Protection",
                "warn",
                "medium" if svc_name == "RemoteRegistry" else "high",
                f"{display} increases attack surface if it is not explicitly required.",
                f"Status={status}; StartType={start}",
                f"Disable {display} service and set it to Disabled startup.",
                True,
                action_map.get(svc_name),
                True,
                True,
            ))
        else:
            findings.append(make_finding(f"service_{svc_name.lower()}", f"{display} is not running", "Network Protection", "pass", "info", f"{display} is installed but not running or auto-starting.", f"Status={status}; StartType={start}", "No action needed."))
    return findings


def check_identity_accounts() -> List[Finding]:
    findings: List[Finding] = []
    ps_guest = r"""
    try { Get-LocalUser -Name Guest -ErrorAction Stop | Select-Object Name,Enabled,PasswordRequired,LastLogon | ConvertTo-Json -Compress }
    catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    result = run_powershell(ps_guest, "guest_user")
    guest = parse_json(result.stdout) if result.ok else None
    if guest and not guest.get("Error"):
        enabled = normalize_bool(guest.get("Enabled"))
        if enabled:
            findings.append(make_finding("guest_user", "Guest account is enabled", "Identity & Access", "fail", "high", "The built-in Guest account is enabled, which can weaken local access control.", f"Guest Enabled={guest.get('Enabled')}", "Disable the built-in Guest account.", True, "disable_guest", True, True))
        else:
            findings.append(make_finding("guest_user", "Guest account is disabled", "Identity & Access", "pass", "info", "The built-in Guest account appears disabled.", f"Guest Enabled={guest.get('Enabled')}", "No action needed."))
    else:
        findings.append(unsupported("guest_user", "Built-in Guest account", "Identity & Access", str(guest.get("Error") if guest else result.stderr or result.stdout)))

    ps_admins = r"""
    try { Get-LocalGroupMember -Group Administrators -ErrorAction Stop | Select-Object Name,ObjectClass,PrincipalSource | ConvertTo-Json -Depth 4 -Compress }
    catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    result = run_powershell(ps_admins, "local_admins")
    admins = parse_json(result.stdout) if result.ok else None
    if admins and not (isinstance(admins, dict) and admins.get("Error")):
        admin_list = ensure_list(admins)
        names = [str(a.get("Name", "Unknown")) for a in admin_list if isinstance(a, dict)]
        if len(names) > 3:
            findings.append(make_finding("local_admins", "Multiple local administrators detected", "Identity & Access", "info", "info", f"{len(names)} principals are in the local Administrators group.", "; ".join(names[:12]), "Review manually. The dashboard does not remove accounts automatically because it cannot know which admin account is legitimate.", False))
        else:
            findings.append(make_finding("local_admins", "Local administrator membership appears limited", "Identity & Access", "pass", "info", f"{len(names)} principal(s) found in the local Administrators group.", "; ".join(names), "No action needed unless an entry is unexpected."))
    else:
        findings.append(unsupported("local_admins", "Local Administrators group", "Identity & Access", str(admins.get("Error") if isinstance(admins, dict) else result.stderr or result.stdout)))

    ps_builtin_admin = r"""
    try { Get-LocalUser -Name Administrator -ErrorAction Stop | Select-Object Name,Enabled,LastLogon | ConvertTo-Json -Compress }
    catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    admin_res = run_powershell(ps_builtin_admin, "builtin_administrator")
    builtin_admin = parse_json(admin_res.stdout) if admin_res.ok else None
    if builtin_admin and not builtin_admin.get("Error"):
        enabled = normalize_bool(builtin_admin.get("Enabled"))
        current_user = os.environ.get("USERNAME", "")
        if enabled and current_user.lower() != "administrator":
            findings.append(make_finding(
                "builtin_administrator",
                "Built-in Administrator account is enabled",
                "Identity & Access",
                "warn",
                "medium",
                "The built-in Administrator account is a predictable high-privilege local account and should usually remain disabled on personal PCs.",
                f"Administrator Enabled={builtin_admin.get('Enabled')}; CurrentUser={current_user}",
                "Disable the built-in Administrator account while keeping your normal named admin account available.",
                True,
                "disable_builtin_administrator",
                True,
                True,
                6,
            ))
        elif enabled:
            findings.append(make_finding(
                "builtin_administrator",
                "Built-in Administrator account is the current user",
                "Identity & Access",
                "info",
                "info",
                "The built-in Administrator account appears enabled and may be the current user. It is not changed automatically to avoid lockout.",
                f"Administrator Enabled={builtin_admin.get('Enabled')}; CurrentUser={current_user}",
                "Create/use a named admin account before disabling the built-in Administrator account.",
            ))
        else:
            findings.append(make_finding("builtin_administrator", "Built-in Administrator account is disabled", "Identity & Access", "pass", "info", "The built-in Administrator account appears disabled.", f"Administrator Enabled={builtin_admin.get('Enabled')}", "No action needed."))
    else:
        findings.append(unsupported("builtin_administrator", "Built-in Administrator account", "Identity & Access", str(builtin_admin.get("Error") if builtin_admin else admin_res.stderr or admin_res.stdout)))

    res = run_command(["net", "accounts"], "password_policy", timeout=15) if is_windows() else CommandResult(False, "", "net command requires Windows", 127, "password_policy")
    if res.ok:
        out = res.stdout
        min_len_match = re.search(r"Minimum password length\s+(\d+)", out, re.IGNORECASE)
        lockout_match = re.search(r"Lockout threshold\s+(Never|\d+)", out, re.IGNORECASE)
        min_len = int(min_len_match.group(1)) if min_len_match else None
        lockout = lockout_match.group(1) if lockout_match else None
        problems = []
        if min_len is not None and min_len < 12:
            problems.append(f"minimum password length is {min_len}")
        if lockout and lockout.lower() == "never":
            problems.append("lockout threshold is Never")
        if problems:
            findings.append(make_finding("password_policy", "Weak local password policy settings", "Identity & Access", "warn", "medium", "Local password policy appears weaker than common baseline recommendations.", "; ".join(problems), "Set minimum length to 12 characters and lockout threshold to 10 failed attempts.", True, "set_machine_password_policy", True, True))
        else:
            findings.append(make_finding("password_policy", "Local password policy baseline appears reasonable", "Identity & Access", "pass", "info", "No obvious weak local password policy values were found from net accounts output.", f"MinimumLength={min_len}; Lockout={lockout}", "No action needed."))
    else:
        findings.append(unsupported("password_policy", "Local password policy", "Identity & Access", res.stderr or res.stdout))
    return findings


def check_windows_security_settings() -> List[Finding]:
    findings: List[Finding] = []
    if is_windows() and winreg:
        ok, enable_lua, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        if ok:
            if int(enable_lua) == 1:
                findings.append(make_finding("uac_enabled", "User Account Control is enabled", "Device Hardening", "pass", "info", "UAC is enabled through EnableLUA.", f"EnableLUA={enable_lua}", "No action needed."))
            else:
                findings.append(make_finding("uac_enabled", "User Account Control is disabled", "Device Hardening", "fail", "high", "UAC helps prevent silent elevation and unsafe administrative changes.", f"EnableLUA={enable_lua}", "Enable UAC. A reboot may be required.", True, "enable_uac", True, True))
        else:
            findings.append(unsupported("uac_enabled", "User Account Control", "Device Hardening", msg))

        ok, hide_ext, msg = registry_get(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt")
        if ok:
            if int(hide_ext) == 1:
                findings.append(make_finding("file_extensions", "Known file extensions are hidden", "User Safety", "warn", "low", "Hidden extensions can make malicious files harder to identify, such as invoice.pdf.exe appearing as invoice.pdf.", f"HideFileExt={hide_ext}", "Show known file extensions in File Explorer.", True, "enable_file_extensions", True, False))
            else:
                findings.append(make_finding("file_extensions", "Known file extensions are visible", "User Safety", "pass", "info", "File Explorer is configured to show known file extensions.", f"HideFileExt={hide_ext}", "No action needed."))
        else:
            findings.append(unsupported("file_extensions", "File extension visibility", "User Safety", msg))

        ok, autorun, msg = registry_get(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
        # If missing, Windows defaults usually disable AutoRun on unknown/network but not all drive types.
        if ok and int(autorun) == 255:
            findings.append(make_finding("autorun", "AutoRun broadly disabled", "User Safety", "pass", "info", "AutoRun appears disabled for all drive types in current-user policy.", f"NoDriveTypeAutoRun={autorun}", "No action needed."))
        else:
            evidence = f"NoDriveTypeAutoRun={autorun}" if ok else msg
            findings.append(make_finding("autorun", "AutoRun policy is not maximally restrictive", "User Safety", "warn", "low", "Restrictive AutoRun settings reduce risk from removable media and legacy autorun behavior.", evidence, "Disable AutoRun for all drive types.", True, "enable_autorun_protection", True, False))

        ok, ppl, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
        if ok and int(ppl) in {1, 2}:
            findings.append(make_finding("lsa_protection", "LSA protection is enabled", "Credential Protection", "pass", "info", "LSA protection appears enabled.", f"RunAsPPL={ppl}", "No action needed."))
        else:
            findings.append(make_finding("lsa_protection", "LSA protection is not enabled", "Credential Protection", "warn", "high", "LSA protection can help reduce credential theft from LSASS memory.", f"RunAsPPL={ppl if ok else msg}", "Enable LSA protection. Reboot required.", True, "enable_lsa_protection", True, True))

        ok, hvci, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled")
        if ok and int(hvci) == 1:
            findings.append(make_finding("memory_integrity", "Memory Integrity / HVCI is enabled", "Credential Protection", "pass", "info", "Hypervisor-enforced code integrity appears enabled.", f"HVCI Enabled={hvci}", "No action needed."))
        else:
            findings.append(make_finding("memory_integrity", "Memory Integrity / HVCI is not enabled", "Credential Protection", "warn", "medium", "Memory Integrity can reduce kernel-level attack risk, but compatibility varies by device and drivers.", f"HVCI Enabled={hvci if ok else msg}", "Enable Memory Integrity. Windows may still keep it off if incompatible drivers are present. Restart may be required.", True, "enable_memory_integrity", True, True, 7))
    else:
        for id_, title, category in [
            ("uac_enabled", "User Account Control", "Device Hardening"),
            ("file_extensions", "File extension visibility", "User Safety"),
            ("autorun", "AutoRun policy", "User Safety"),
            ("lsa_protection", "LSA protection", "Credential Protection"),
            ("memory_integrity", "Memory Integrity / HVCI", "Credential Protection"),
        ]:
            findings.append(unsupported(id_, title, category, "Windows registry unavailable."))


    # Windows SmartScreen / app reputation controls.
    if is_windows() and winreg:
        ok, smartscreen, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled")
        ok2, apphost, msg2 = registry_get(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\AppHost", "EnableWebContentEvaluation")
        smart_off = (ok and str(smartscreen).lower() == "off") or (ok2 and int(apphost) == 0)
        if smart_off:
            findings.append(make_finding(
                "windows_smartscreen",
                "Windows SmartScreen or app reputation checks are disabled",
                "User Safety",
                "warn",
                "medium",
                "SmartScreen helps warn against malicious downloads, phishing, and low-reputation apps.",
                f"SmartScreenEnabled={smartscreen if ok else msg}; EnableWebContentEvaluation={apphost if ok2 else msg2}",
                "Enable Windows SmartScreen and app reputation checks.",
                True,
                "enable_smartscreen",
                True,
                True,
                6,
            ))
        else:
            findings.append(make_finding(
                "windows_smartscreen",
                "Windows SmartScreen/app reputation checks appear enabled or managed",
                "User Safety",
                "pass",
                "info",
                "SmartScreen-related registry values do not appear disabled.",
                f"SmartScreenEnabled={smartscreen if ok else msg}; EnableWebContentEvaluation={apphost if ok2 else msg2}",
                "No action needed.",
            ))

        ok, guest_auth, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "AllowInsecureGuestAuth")
        if ok and int(guest_auth) != 0:
            findings.append(make_finding(
                "insecure_smb_guest_auth",
                "Insecure SMB guest authentication is allowed",
                "Network Protection",
                "warn",
                "medium",
                "Insecure SMB guest authentication weakens network file-sharing authentication.",
                f"AllowInsecureGuestAuth={guest_auth}",
                "Disable insecure SMB guest authentication.",
                True,
                "disable_insecure_guest_auth",
                True,
                True,
                6,
            ))
        else:
            findings.append(make_finding(
                "insecure_smb_guest_auth",
                "Insecure SMB guest authentication is disabled or absent",
                "Network Protection",
                "pass",
                "info",
                "The insecure SMB guest authentication registry value does not appear enabled.",
                f"AllowInsecureGuestAuth={guest_auth if ok else msg}",
                "No action needed.",
            ))

        ok, restrict_anon, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous")
        if (not ok) or int(restrict_anon) < 1:
            findings.append(make_finding(
                "restrict_anonymous_enumeration",
                "Anonymous enumeration restrictions are weak or unset",
                "Identity & Access",
                "warn",
                "low",
                "Restricting anonymous enumeration reduces information exposure to unauthenticated network users.",
                f"RestrictAnonymous={restrict_anon if ok else msg}",
                "Enable basic anonymous enumeration restrictions.",
                True,
                "enable_restrict_anonymous",
                True,
                True,
                4,
            ))
        else:
            findings.append(make_finding(
                "restrict_anonymous_enumeration",
                "Anonymous enumeration is restricted",
                "Identity & Access",
                "pass",
                "info",
                "RestrictAnonymous is set to a restrictive value.",
                f"RestrictAnonymous={restrict_anon}",
                "No action needed.",
            ))

    ps_ps2 = r"""
    try {
      $feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop | Select-Object FeatureName,State
      $feature | ConvertTo-Json -Compress
    } catch {
      try {
        $dism = (dism.exe /online /Get-FeatureInfo /FeatureName:MicrosoftWindowsPowerShellV2Root 2>$null) -join "`n"
        $state = if($dism -match 'State\s*:\s*Enabled'){ 'Enabled' } elseif($dism -match 'State\s*:\s*Disabled'){ 'Disabled' } else { 'Unknown' }
        [pscustomobject]@{ FeatureName='MicrosoftWindowsPowerShellV2Root'; State=$state; Source='DISM' } | ConvertTo-Json -Compress
      } catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    }
    """
    ps2_res = run_powershell(ps_ps2, "powershell_v2_status")
    ps2 = parse_json(ps2_res.stdout) if ps2_res.ok else None
    if ps2 and not ps2.get("Error"):
        state = str(ps2.get("State"))
        if state.lower() == "enabled":
            findings.append(make_finding(
                "powershell_v2",
                "PowerShell 2.0 compatibility feature is enabled",
                "Script Safety",
                "warn",
                "medium",
                "PowerShell 2.0 lacks modern security logging and should be disabled unless required for legacy compatibility.",
                f"State={state}",
                "Disable the PowerShell 2.0 optional feature.",
                True,
                "disable_powershell_v2",
                True,
                True,
                6,
            ))
        else:
            findings.append(make_finding("powershell_v2", "PowerShell 2.0 feature is disabled", "Script Safety", "pass", "info", "The PowerShell 2.0 optional feature is not enabled.", f"State={state}", "No action needed."))
    else:
        # Some Windows Home / Insider builds do not expose this optional feature
        # through Get-WindowsOptionalFeature or DISM even when run elevated. Do
        # not treat that as a user-facing risk; surface it as informational so a
        # Keep this informational to avoid a false negative score impact.
        findings.append(make_finding(
            "powershell_v2",
            "PowerShell 2.0 optional feature could not be confirmed",
            "Script Safety",
            "info",
            "info",
            "Windows did not return a reliable PowerShell 2.0 optional-feature state.",
            str(ps2.get("Error") if ps2 else ps2_res.stderr or ps2_res.stdout),
            "No automatic action was taken because this Windows build did not expose the feature state.",
        ))

    ps_ep = r"""
    $pol = Get-ExecutionPolicy -List -ErrorAction SilentlyContinue | Select-Object Scope,ExecutionPolicy
    $pol | ConvertTo-Json -Depth 4 -Compress
    """
    res = run_powershell(ps_ep, "powershell_execution_policy")
    policies = ensure_list(parse_json(res.stdout)) if res.ok else []
    if policies:
        risky = [p for p in policies if str(p.get("ExecutionPolicy", "")).lower() in {"unrestricted", "bypass"} and str(p.get("Scope", "")).lower() in {"localmachine", "currentuser"}]
        if risky:
            findings.append(make_finding("powershell_execution_policy", "PowerShell execution policy is permissive", "Script Safety", "warn", "low", "PowerShell policy is set to Unrestricted or Bypass at CurrentUser or LocalMachine scope.", json.dumps(risky), "Use RemoteSigned or a stricter policy unless your workflow requires otherwise.", True, "set_powershell_remote_signed", True, False))
        else:
            findings.append(make_finding("powershell_execution_policy", "PowerShell execution policy is not broadly permissive", "Script Safety", "pass", "info", "CurrentUser and LocalMachine PowerShell execution policies are not Unrestricted/Bypass.", json.dumps(policies), "No action needed."))
    else:
        findings.append(unsupported("powershell_execution_policy", "PowerShell execution policy", "Script Safety", res.stderr or res.stdout))
    return findings


def check_network_exposure() -> List[Finding]:
    ps = r"""
    $conns = Get-NetTCPConnection -State Listen -ErrorAction Stop |
      Select-Object LocalAddress,LocalPort,OwningProcess
    $procs = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
    $conns | ForEach-Object {
      [pscustomobject]@{ LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; Process=$procs[[int]$_.OwningProcess]; PID=$_.OwningProcess }
    } | ConvertTo-Json -Depth 4 -Compress
    """
    result = run_powershell(ps, "listening_ports")
    if not result.ok:
        return [unsupported("listening_ports", "Listening network ports", "Network Exposure", result.stderr or result.stdout)]
    conns = ensure_list(parse_json(result.stdout))
    risky_ports = {21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 5985: "WinRM HTTP", 5986: "WinRM HTTPS"}
    risky = []
    for c in conns:
        try:
            port = int(c.get("LocalPort"))
        except Exception:
            continue
        addr = str(c.get("LocalAddress", ""))
        if port in risky_ports and addr in {"0.0.0.0", "::", "::0", "*"}:
            risky.append({"port": port, "service": risky_ports[port], "address": addr, "process": c.get("Process"), "pid": c.get("PID")})
    findings: List[Finding] = []
    if risky:
        risky_port_set = {int(item["port"]) for item in risky if "port" in item}
        only_default_windows_services = risky_port_set.issubset({135, 139, 445})
        block_rule_present = risky_port_block_rule_exists()
        if block_rule_present or (only_default_windows_services and firewall_profiles_are_protective()):
            reason = "an explicit dashboard firewall block rule is enabled" if block_rule_present else "Windows Firewall profiles are enabled with inbound traffic blocked by default"
            findings.append(make_finding(
                "listening_risky_ports",
                "Risky/default network listeners are firewall-protected",
                "Network Exposure",
                "pass",
                "info",
                f"Broadly listening RPC/SMB/remote-service endpoints were found, but {reason}.",
                json.dumps(risky[:12], ensure_ascii=False),
                "No action needed unless you intentionally expose file sharing or remote administration to untrusted networks.",
            ))
        else:
            findings.append(make_finding(
                "listening_risky_ports",
                "Risky network services may be exposed",
                "Network Exposure",
                "warn",
                "high" if not only_default_windows_services else "medium",
                f"{len(risky)} risky listening endpoint(s) were found on all interfaces. The dashboard can add firewall block rules for common risky inbound services.",
                json.dumps(risky[:12], ensure_ascii=False),
                "Add Windows Firewall block rules for common risky inbound services that should not be exposed on a personal PC.",
                True,
                "block_risky_inbound_ports",
                True,
                True,
                12 if not only_default_windows_services else 6,
            ))
    else:
        findings.append(make_finding("listening_risky_ports", "No broadly listening high-risk ports found", "Network Exposure", "pass", "info", "Common high-risk ports were not found listening on all interfaces.", f"Total listening endpoints scanned={len(conns)}", "No action needed."))

    total = len(conns)
    if total > 80:
        findings.append(make_finding("listening_port_count", "Large number of listening ports", "Network Exposure", "warn", "low", f"The system has {total} listening TCP endpoints, which may be normal for developer machines but warrants review.", f"Total={total}", "Block common risky inbound ports with Windows Firewall and review any remaining unexpected listeners.", True, "block_risky_inbound_ports", True, True, 4))
    else:
        findings.append(make_finding("listening_port_count", "Listening port count is not unusually high", "Network Exposure", "pass", "info", f"The system has {total} listening TCP endpoint(s).", f"Total={total}", "No action needed."))
    return findings


def check_hosts_startup_audit() -> List[Finding]:
    findings: List[Finding] = []
    # Hosts file review
    hosts_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    if is_windows() and hosts_path.exists():
        try:
            lines = hosts_path.read_text(encoding="utf-8", errors="replace").splitlines()
            entries = []
            suspicious_terms = ["microsoft", "windowsupdate", "defender", "security", "google", "github", "virustotal"]
            suspicious = []
            for raw in lines:
                stripped = raw.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                entries.append(stripped)
                if any(term in stripped.lower() for term in suspicious_terms):
                    suspicious.append(stripped)
            if suspicious:
                findings.append(make_finding("hosts_file", "Hosts file contains security-sensitive mappings", "System Integrity", "warn", "medium", "The hosts file contains entries involving update, security, or common service domains.", "; ".join(suspicious[:8]), "Back up the hosts file and remove suspicious update/security-domain mappings.", True, "clean_suspicious_hosts", True, True))
            else:
                findings.append(make_finding("hosts_file", "Hosts file does not contain obvious risky mappings", "System Integrity", "pass", "info", f"Hosts file has {len(entries)} active non-comment entrie(s).", f"ActiveEntries={len(entries)}", "No action needed unless entries are unexpected."))
        except PermissionError:
            findings.append(unsupported("hosts_file", "Hosts file review", "System Integrity", "Permission denied reading hosts file."))
        except Exception as exc:
            findings.append(unsupported("hosts_file", "Hosts file review", "System Integrity", str(exc)))
    else:
        findings.append(unsupported("hosts_file", "Hosts file review", "System Integrity", "Hosts file not found or non-Windows system."))

    # Startup registry count
    startup_items: List[str] = []
    if is_windows() and winreg:
        locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM WOW6432 Run"),
        ]
        for root, path, label in locations:
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            startup_items.append(f"{label}:{name}")
                            i += 1
                        except OSError:
                            break
            except Exception:
                continue
        if len(startup_items) > 15:
            findings.append(make_finding("startup_items", "Many startup entries detected", "System Integrity", "info", "info", f"{len(startup_items)} registry startup entries were found.", "; ".join(startup_items[:15]), "Review manually. The dashboard does not delete startup entries automatically because it cannot know which apps are wanted.", False))
        else:
            findings.append(make_finding("startup_items", "Startup entry count is not unusually high", "System Integrity", "pass", "info", f"{len(startup_items)} registry startup entries were found.", "; ".join(startup_items[:15]) or "None", "No action needed unless an entry is unexpected."))
    else:
        findings.append(unsupported("startup_items", "Registry startup entries", "System Integrity", "Windows registry unavailable."))

    # Audit policy: check logon failure auditing.
    res = run_command(["auditpol", "/get", "/subcategory:Logon", "/r"], "audit_logon_policy", timeout=15) if is_windows() else CommandResult(False, "", "auditpol requires Windows", 127, "audit_logon_policy")
    if res.ok:
        out = res.stdout.strip()
        has_failure = "Failure" in out
        has_success = "Success" in out
        if has_failure:
            findings.append(make_finding("audit_logon_policy", "Logon auditing includes failures", "Monitoring", "pass", "info", "Windows audit policy appears to include failed logon auditing.", out[:500], "No action needed."))
        else:
            findings.append(make_finding("audit_logon_policy", "Failed logon auditing may be disabled", "Monitoring", "warn", "low", "Failed logon auditing helps investigate brute-force attempts and unauthorized access attempts.", out[:500], "Enable failure auditing for logon events.", True, "enable_failed_logon_audit", True, True))
    else:
        findings.append(unsupported("audit_logon_policy", "Logon audit policy", "Monitoring", res.stderr or res.stdout))
    return findings



def check_credential_network_hardening() -> List[Finding]:
    """Registry-backed hardening checks that are free and directly remediable."""
    findings: List[Finding] = []
    if not (is_windows() and winreg):
        for id_, title, category in [
            ("wdigest_protection", "WDigest credential caching", "Credential Protection"),
            ("lm_compatibility", "NTLM/LM compatibility level", "Credential Protection"),
            ("blank_password_restriction", "Blank-password network logon restriction", "Identity & Access"),
            ("smb_signing", "SMB signing policy", "Network Protection"),
            ("llmnr", "LLMNR name resolution", "Network Protection"),
        ]:
            findings.append(unsupported(id_, title, category, "Windows registry unavailable."))
        return findings

    ok, wdigest, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential")
    if ok and int(wdigest) != 0:
        findings.append(make_finding(
            "wdigest_protection",
            "WDigest credential caching is enabled",
            "Credential Protection",
            "warn",
            "high",
            "WDigest credential caching can expose reusable credentials in memory.",
            f"UseLogonCredential={wdigest}",
            "Disable WDigest credential caching.",
            True,
            "enable_wdigest_protection",
            True,
            True,
            10,
        ))
    else:
        findings.append(make_finding(
            "wdigest_protection",
            "WDigest credential caching is disabled or absent",
            "Credential Protection",
            "pass",
            "info",
            "WDigest UseLogonCredential is not enabled.",
            f"UseLogonCredential={wdigest if ok else msg}",
            "No action needed.",
        ))

    ok, lm_level, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel")
    if not ok or int(lm_level) < 5:
        findings.append(make_finding(
            "lm_compatibility",
            "LM/NTLM compatibility level is not hardened",
            "Credential Protection",
            "warn",
            "medium",
            "Older LM/NTLM compatibility settings can allow weaker authentication behavior.",
            f"LmCompatibilityLevel={lm_level if ok else msg}",
            "Set LmCompatibilityLevel to 5 to refuse LM and NTLM responses where supported.",
            True,
            "set_lm_compatibility_level",
            True,
            True,
            6,
        ))
    else:
        findings.append(make_finding("lm_compatibility", "LM/NTLM compatibility level is hardened", "Credential Protection", "pass", "info", "LmCompatibilityLevel is set to a hardened value.", f"LmCompatibilityLevel={lm_level}", "No action needed."))

    ok, limit_blank, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse")
    if not ok or int(limit_blank) != 1:
        findings.append(make_finding(
            "blank_password_restriction",
            "Blank-password network logon restriction is weak or unset",
            "Identity & Access",
            "warn",
            "medium",
            "Windows should prevent local accounts with blank passwords from authenticating over the network.",
            f"LimitBlankPasswordUse={limit_blank if ok else msg}",
            "Enable the blank-password network logon restriction.",
            True,
            "enable_blank_password_restriction",
            True,
            True,
            6,
        ))
    else:
        findings.append(make_finding("blank_password_restriction", "Blank-password network logon restriction is enabled", "Identity & Access", "pass", "info", "LimitBlankPasswordUse is enabled.", f"LimitBlankPasswordUse={limit_blank}", "No action needed."))

    smb_paths = [
        (r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnableSecuritySignature", "Workstation EnableSecuritySignature"),
        (r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", "Workstation RequireSecuritySignature"),
        (r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSecuritySignature", "Server EnableSecuritySignature"),
        (r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", "Server RequireSecuritySignature"),
    ]
    smb_values = []
    smb_weak = []
    for path, name, label in smb_paths:
        ok, value, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, path, name)
        smb_values.append(f"{label}={value if ok else msg}")
        if not ok or int(value) != 1:
            smb_weak.append(label)
    if smb_weak:
        findings.append(make_finding(
            "smb_signing",
            "SMB signing policy is not fully required",
            "Network Protection",
            "warn",
            "medium",
            "SMB signing helps reduce relay and tampering risk for SMB traffic.",
            "; ".join(smb_values),
            "Enable and require SMB signing for client and server components.",
            True,
            "enable_smb_signing",
            True,
            True,
            6,
        ))
    else:
        findings.append(make_finding("smb_signing", "SMB signing is enabled and required", "Network Protection", "pass", "info", "Client and server SMB signing values are enabled and required.", "; ".join(smb_values), "No action needed."))

    ok, llmnr, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast")
    if not ok or int(llmnr) != 0:
        findings.append(make_finding(
            "llmnr",
            "LLMNR is not disabled by policy",
            "Network Protection",
            "warn",
            "low",
            "LLMNR can assist local-network spoofing and credential relay attacks on untrusted networks.",
            f"EnableMulticast={llmnr if ok else msg}",
            "Disable LLMNR multicast name resolution by policy.",
            True,
            "disable_llmnr",
            True,
            True,
            4,
        ))
    else:
        findings.append(make_finding("llmnr", "LLMNR is disabled by policy", "Network Protection", "pass", "info", "LLMNR multicast name resolution is disabled by policy.", f"EnableMulticast={llmnr}", "No action needed."))
    return findings


def check_security_service_baselines() -> List[Finding]:
    """Check that security/update-related Windows services are not disabled."""
    findings: List[Finding] = []
    ps = r"""
    $names = @('wuauserv','bits','wscsvc','SecurityHealthService','WinDefend')
    $rows = foreach ($n in $names) {
      $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
      if ($svc) { [pscustomobject]@{ Name=$svc.Name; Status=$svc.Status; StartType=$svc.StartType } }
      else { [pscustomobject]@{ Name=$n; Missing=$true } }
    }
    $rows | ConvertTo-Json -Depth 5 -Compress
    """
    res = run_powershell(ps, "security_services", timeout=15)
    rows = ensure_list(parse_json(res.stdout)) if res.ok else []
    if not rows:
        return [unsupported("security_services", "Security and update services", "System Integrity", res.stderr or res.stdout)]

    disabled_update = [r.get("Name") for r in rows if r.get("Name") in {"wuauserv", "bits"} and str(r.get("StartType", "")).lower() == "disabled"]
    disabled_security = [r.get("Name") for r in rows if r.get("Name") in {"wscsvc", "SecurityHealthService", "WinDefend"} and str(r.get("StartType", "")).lower() == "disabled"]
    evidence = json.dumps(rows, ensure_ascii=False)

    if disabled_update:
        findings.append(make_finding(
            "windows_update_services",
            "Windows Update support services are disabled",
            "Patch Management",
            "warn",
            "high",
            f"Required update service(s) are disabled: {', '.join(disabled_update)}.",
            evidence,
            "Re-enable Windows Update and BITS services so security updates can download and install.",
            True,
            "enable_windows_update_services",
            True,
            True,
            10,
        ))
    else:
        findings.append(make_finding("windows_update_services", "Windows Update support services are available", "Patch Management", "pass", "info", "Windows Update and BITS services are not disabled.", evidence, "No action needed."))

    if disabled_security:
        findings.append(make_finding(
            "security_center_services",
            "Windows security services are disabled",
            "Endpoint Protection",
            "warn",
            "high",
            f"Security service(s) are disabled: {', '.join(disabled_security)}.",
            evidence,
            "Re-enable Windows Security Center / Defender services where the OS allows it.",
            True,
            "start_security_services",
            True,
            True,
            10,
        ))
    else:
        findings.append(make_finding("security_center_services", "Windows security services are available", "Endpoint Protection", "pass", "info", "Core Windows security services are not disabled.", evidence, "No action needed."))
    return findings


def check_logging_hardening() -> List[Finding]:
    findings: List[Finding] = []
    # Process creation auditing with command line capture.
    audit_res = run_command(["auditpol", "/get", "/subcategory:Process Creation", "/r"], "audit_process_creation", timeout=15) if is_windows() else CommandResult(False, "", "auditpol requires Windows", 127, "audit_process_creation")
    ok, cmdline, msg = (registry_get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled") if is_windows() and winreg else (False, None, "Windows registry unavailable"))
    audit_ok = audit_res.ok and "Success" in audit_res.stdout
    cmdline_ok = ok and int(cmdline) == 1
    if not (audit_ok and cmdline_ok):
        findings.append(make_finding(
            "process_creation_auditing",
            "Process creation auditing is not fully enabled",
            "Monitoring",
            "warn",
            "low",
            "Process creation auditing with command-line capture improves local incident investigation and malware triage.",
            f"auditpol_success={audit_ok}; ProcessCreationIncludeCmdLine_Enabled={cmdline if ok else msg}",
            "Enable process creation auditing and command-line logging.",
            True,
            "enable_process_creation_auditing",
            True,
            True,
            4,
        ))
    else:
        findings.append(make_finding("process_creation_auditing", "Process creation auditing is enabled", "Monitoring", "pass", "info", "Process creation auditing and command-line capture appear enabled.", f"auditpol_success={audit_ok}; ProcessCreationIncludeCmdLine_Enabled={cmdline}", "No action needed."))

    if is_windows() and winreg:
        checks = [
            (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", "ScriptBlock"),
            (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", "Module"),
            (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting", "Transcription"),
        ]
        values = []
        missing = []
        for path, name, label in checks:
            ok, value, msg = registry_get(winreg.HKEY_LOCAL_MACHINE, path, name)
            values.append(f"{label}={value if ok else msg}")
            if not ok or int(value) != 1:
                missing.append(label)
        if missing:
            findings.append(make_finding(
                "powershell_logging",
                "PowerShell security logging is incomplete",
                "Monitoring",
                "warn",
                "low",
                f"PowerShell {', '.join(missing)} logging is not enabled by policy.",
                "; ".join(values),
                "Enable PowerShell script block logging, module logging, and transcription to improve investigation visibility.",
                True,
                "enable_powershell_logging",
                True,
                True,
                4,
            ))
        else:
            findings.append(make_finding("powershell_logging", "PowerShell security logging is enabled", "Monitoring", "pass", "info", "Script block, module, and transcription logging are enabled by policy.", "; ".join(values), "No action needed."))
    else:
        findings.append(unsupported("powershell_logging", "PowerShell security logging", "Monitoring", "Windows registry unavailable."))
    return findings



def _reg_value_text(root: Any, path: str, name: str) -> Tuple[bool, str, Any]:
    ok, value, msg = registry_get(root, path, name)
    return ok, (str(value) if ok else msg), value


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return None


def check_additional_hardening() -> List[Finding]:
    """Additional free Windows hardening checks with automatic allowlisted fixes.

    These controls are intentionally conservative for a personal Windows PC: they do
    not require paid upgrades, third-party tools, or cloud accounts. They focus on
    reducing exposed management surfaces, hardening credential handling, improving
    auditability, and enforcing common anti-phishing / anti-malware policies.
    """
    findings: List[Finding] = []
    if not is_windows() or winreg is None:
        return [unsupported("additional_hardening", "Additional Windows hardening checks", "Hardening", "Windows registry unavailable.")]

    # Firewall management groups that are often unnecessary on a personal PC.
    ps_groups = r"""
    $groups = @('Core Networking Diagnostics','Remote Event Log Management','Remote Service Management','Windows Management Instrumentation (WMI)','Windows Remote Management')
    $out = foreach($g in $groups){
      $rules = @(Get-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' })
      [pscustomobject]@{ Group=$g; Count=$rules.Count; Names=@($rules | Select-Object -First 10 -ExpandProperty DisplayName) }
    }
    $out | ConvertTo-Json -Depth 5 -Compress
    """
    grp_res = run_powershell(ps_groups, "remote_management_firewall_groups", timeout=20)
    grp_data = ensure_list(parse_json(grp_res.stdout)) if grp_res.ok else []
    enabled_groups = [g for g in grp_data if int(g.get("Count") or 0) > 0]
    if enabled_groups:
        findings.append(make_finding(
            "remote_management_firewall_groups",
            "Remote management firewall groups are enabled",
            "Network Protection",
            "warn",
            "medium",
            f"{sum(int(g.get('Count') or 0) for g in enabled_groups)} inbound remote-management firewall rule(s) are enabled.",
            json.dumps(enabled_groups, ensure_ascii=False),
            "Disable inbound remote-management firewall rule groups unless this PC is intentionally administered over the network.",
            True,
            "disable_remote_management_firewall_rules",
            True,
            True,
            6,
        ))
    elif grp_res.ok:
        findings.append(make_finding("remote_management_firewall_groups", "Remote management firewall groups are not enabled", "Network Protection", "pass", "info", "No enabled inbound remote-management firewall rule groups were found.", json.dumps(grp_data, ensure_ascii=False), "No action needed."))
    else:
        findings.append(unsupported("remote_management_firewall_groups", "Remote management firewall groups", "Network Protection", grp_res.stderr or grp_res.stdout))

    ps_icmp = r"""
    $rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Where-Object { $_.Protocol -eq 'ICMPv4' -or $_.Protocol -eq 'ICMPv6' })
    [pscustomobject]@{ Count=$rules.Count } | ConvertTo-Json -Compress
    """
    icmp_res = run_powershell(ps_icmp, "icmp_echo_rules", timeout=15)
    icmp_data = parse_json(icmp_res.stdout) if icmp_res.ok else None
    if icmp_data and int(icmp_data.get("Count") or 0) > 0:
        findings.append(make_finding("icmp_echo_inbound", "Inbound ICMP echo rules are enabled", "Network Protection", "warn", "low", "Inbound ping/ICMP allow rules can make a device easier to discover on untrusted networks.", f"EnabledICMPRules={icmp_data.get('Count')}", "Disable inbound ICMP echo firewall rules unless needed for troubleshooting.", True, "disable_icmp_echo_firewall_rules", True, True, 4))
    elif icmp_data:
        findings.append(make_finding("icmp_echo_inbound", "Inbound ICMP echo rules are not enabled", "Network Protection", "pass", "info", "No enabled inbound ICMP firewall allow rules were found.", f"EnabledICMPRules={icmp_data.get('Count')}", "No action needed."))

    # Firewall stealth mode is exposed inconsistently across Windows builds.
    # Prefer registry-backed detection/remediation over Set-NetFirewallProfile so
    # the dashboard works on Windows Home and Insider builds where the parameter
    # is missing from the PowerShell module.
    stealth_profiles = []
    for profile_name, reg_profile in [("Domain", "DomainProfile"), ("Private", "StandardProfile"), ("Public", "PublicProfile")]:
        ok, val_text, val = _reg_value_text(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{reg_profile}",
            "DisableUnicastResponsesToMulticastBroadcast",
        )
        stealth_profiles.append({"Name": profile_name, "RegistryProfile": reg_profile, "Value": val if ok else None, "Evidence": val_text})
    stealth_hardened = all(_int_or_none(p.get("Value")) == 1 for p in stealth_profiles)
    if not stealth_hardened:
        findings.append(make_finding("firewall_stealth_mode", "Firewall multicast-response hardening is incomplete", "Network Protection", "warn", "low", "One or more firewall profiles may respond to multicast/broadcast probes.", json.dumps({"Hardened": False, "Profiles": stealth_profiles}, ensure_ascii=False), "Enable firewall profile hardening to reduce unsolicited network discovery responses.", True, "enable_firewall_stealth_mode", True, True, 4))
    else:
        findings.append(make_finding("firewall_stealth_mode", "Firewall multicast-response hardening is enabled", "Network Protection", "pass", "info", "Firewall profile registry values suppress unicast responses to multicast/broadcast probes.", json.dumps({"Hardened": True, "Profiles": stealth_profiles}, ensure_ascii=False), "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop")
    if not ok or _int_or_none(val) != 1:
        findings.append(make_finding("uac_secure_desktop", "UAC secure-desktop prompt is not enforced", "Device Hardening", "warn", "medium", "Admin elevation prompts should occur on the secure desktop to reduce spoofing risk.", f"PromptOnSecureDesktop={val_text}", "Require UAC prompts to use the secure desktop.", True, "enforce_uac_secure_desktop", True, True, 6))
    else:
        findings.append(make_finding("uac_secure_desktop", "UAC secure-desktop prompt is enforced", "Device Hardening", "pass", "info", "UAC prompts are configured to use the secure desktop.", f"PromptOnSecureDesktop={val}", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
    if ok and str(val) == "1":
        findings.append(make_finding("auto_admin_logon", "Automatic admin logon is enabled", "Identity & Access", "fail", "high", "AutoAdminLogon can leave credentials stored in the registry and automatically sign in after boot.", f"AutoAdminLogon={val}", "Disable AutoAdminLogon and clear any stored default password value.", True, "disable_auto_admin_logon", True, True, 12))
    else:
        findings.append(make_finding("auto_admin_logon", "Automatic admin logon is not enabled", "Identity & Access", "pass", "info", "AutoAdminLogon does not appear enabled.", f"AutoAdminLogon={val_text}", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash")
    if not ok or _int_or_none(val) != 1:
        findings.append(make_finding("no_lm_hash", "LAN Manager hash storage is not explicitly disabled", "Credential Protection", "warn", "medium", "LM hashes are obsolete and weaker than modern Windows credential storage.", f"NoLMHash={val_text}", "Prevent Windows from storing LAN Manager password hashes.", True, "enable_no_lm_hash", True, True, 6))
    else:
        findings.append(make_finding("no_lm_hash", "LAN Manager hash storage is disabled", "Credential Protection", "pass", "info", "NoLMHash is enabled.", f"NoLMHash={val}", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")
    cached = _int_or_none(val) if ok else None
    if cached is not None and cached > 10:
        findings.append(make_finding("cached_logons", "Cached domain logon count is high", "Credential Protection", "warn", "low", f"Windows is configured to cache {cached} domain logon(s).", f"CachedLogonsCount={cached}", "Limit cached logons to a conservative maximum of 10.", True, "limit_cached_logons", True, True, 4))
    else:
        findings.append(make_finding("cached_logons", "Cached logon count is not high", "Credential Protection", "pass", "info", "CachedLogonsCount is absent/default or not greater than 10.", f"CachedLogonsCount={val_text}", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\CredUI", "DisablePasswordReveal")
    if not ok or _int_or_none(val) != 1:
        findings.append(make_finding("password_reveal", "Password reveal button is not disabled by policy", "User Safety", "warn", "low", "The password reveal UI can increase shoulder-surfing risk on shared or public screens.", f"DisablePasswordReveal={val_text}", "Disable the password reveal button through Windows policy.", True, "disable_password_reveal", True, True, 3))
    else:
        findings.append(make_finding("password_reveal", "Password reveal button is disabled by policy", "User Safety", "pass", "info", "The password reveal button is disabled by policy.", f"DisablePasswordReveal={val}", "No action needed."))

    # Obsolete TLS/SSL protocol hardening. Missing values are not automatically treated as vulnerable on modern Windows.
    old_proto_findings = []
    for proto in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]:
        for role in ["Client", "Server"]:
            path = rf"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{proto}\{role}"
            ok_e, enabled, _ = registry_get(winreg.HKEY_LOCAL_MACHINE, path, "Enabled")
            if ok_e and _int_or_none(enabled) == 1:
                old_proto_findings.append(f"{proto} {role} Enabled=1")
    if old_proto_findings:
        findings.append(make_finding("obsolete_tls_protocols", "Obsolete SSL/TLS protocols are explicitly enabled", "Network Protection", "warn", "medium", "One or more obsolete SSL/TLS protocols are explicitly enabled in SCHANNEL.", "; ".join(old_proto_findings), "Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 for client/server SCHANNEL roles.", True, "harden_tls_defaults", True, True, 6))
    else:
        findings.append(make_finding("obsolete_tls_protocols", "Obsolete SSL/TLS protocols are not explicitly enabled", "Network Protection", "pass", "info", "No explicit registry enablement was found for SSL 2.0, SSL 3.0, TLS 1.0, or TLS 1.1.", "Checked SCHANNEL protocol registry keys.", "No action needed."))

    # Office documents from the internet: strong phishing/macro control.
    missing_office = []
    for app in ["Word", "Excel", "PowerPoint"]:
        path = rf"Software\Policies\Microsoft\Office\16.0\{app}\Security"
        ok, v, _ = registry_get(winreg.HKEY_CURRENT_USER, path, "blockcontentexecutionfrominternet")
        if not ok or _int_or_none(v) != 1:
            missing_office.append(app)
    if missing_office:
        findings.append(make_finding("office_internet_macros", "Office internet macro blocking is not fully enforced", "Application Hardening", "warn", "medium", f"Office macro blocking from internet documents is not enforced for: {', '.join(missing_office)}.", f"Missing={missing_office}", "Block macro execution in Word, Excel, and PowerPoint documents originating from the internet.", True, "block_office_internet_macros", True, True, 6))
    else:
        findings.append(make_finding("office_internet_macros", "Office internet macro blocking is enforced", "Application Hardening", "pass", "info", "Word, Excel, and PowerPoint policies block macro execution from internet-origin documents.", "Office 16.0 policy keys present for Word/Excel/PowerPoint.", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config", "DODownloadMode")
    if ok and _int_or_none(val) == 3:
        findings.append(make_finding("delivery_optimization_p2p", "Delivery Optimization internet peer downloads are enabled", "Patch Management", "warn", "low", "Delivery Optimization can download/upload update content with internet peers when configured for internet mode.", f"DODownloadMode={val}", "Restrict Delivery Optimization to HTTP-only or local-only behavior.", True, "disable_delivery_optimization_internet_peer", True, True, 3))
    else:
        findings.append(make_finding("delivery_optimization_p2p", "Delivery Optimization internet peer mode is not enabled", "Patch Management", "pass", "info", "Delivery Optimization internet peer mode does not appear enabled.", f"DODownloadMode={val_text}", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled")
    if ok and _int_or_none(val) == 1:
        findings.append(make_finding("advertising_id", "Windows advertising ID is enabled", "Privacy Hardening", "warn", "low", "Advertising ID is not a direct compromise risk, but disabling it reduces cross-app tracking on the PC.", f"AdvertisingInfo Enabled={val}", "Disable Windows advertising ID for the current user.", True, "disable_advertising_id", True, False, 2))
    else:
        findings.append(make_finding("advertising_id", "Windows advertising ID is disabled or absent", "Privacy Hardening", "pass", "info", "Advertising ID does not appear enabled for the current user.", f"AdvertisingInfo Enabled={val_text}", "No action needed."))

    clipboard_risky = []
    for name in ["EnableClipboardHistory", "EnableCloudClipboard"]:
        ok, v, msg = registry_get(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard", name)
        if ok and _int_or_none(v) == 1:
            clipboard_risky.append(f"{name}=1")
    if clipboard_risky:
        findings.append(make_finding("clipboard_cloud", "Clipboard history/cloud clipboard is enabled", "Privacy Hardening", "warn", "low", "Clipboard history and cloud clipboard can retain sensitive copied data.", "; ".join(clipboard_risky), "Disable clipboard history and cloud clipboard sync.", True, "disable_clipboard_cloud", True, False, 3))
    else:
        findings.append(make_finding("clipboard_cloud", "Clipboard history/cloud clipboard is disabled or absent", "Privacy Hardening", "pass", "info", "Clipboard history/cloud clipboard values do not appear enabled.", "Checked EnableClipboardHistory and EnableCloudClipboard.", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", "DisableAutoplay")
    if not ok or _int_or_none(val) != 1:
        findings.append(make_finding("autoplay_policy", "AutoPlay is not explicitly disabled", "User Safety", "warn", "low", "Disabling AutoPlay reduces risk from removable-media social engineering and accidental execution paths.", f"DisableAutoplay={val_text}", "Disable AutoPlay for the current user and reinforce AutoRun protection.", True, "harden_autoplay_policy", True, True, 3))
    else:
        findings.append(make_finding("autoplay_policy", "AutoPlay is disabled", "User Safety", "pass", "info", "AutoPlay is disabled for the current user.", f"DisableAutoplay={val}", "No action needed."))

    # Event log capacity and retention: useful for forensic visibility.
    log_issues = []
    for log in ["Security", "System", "Application", "Windows PowerShell"]:
        ps_log = f"""
        try {{ $l=Get-EventLog -List | Where-Object {{ $_.Log -eq '{log}' }}; [pscustomobject]@{{ Log='{log}'; MaximumKilobytes=$l.MaximumKilobytes }} | ConvertTo-Json -Compress }} catch {{ [pscustomobject]@{{ Log='{log}'; Error=$_.Exception.Message }} | ConvertTo-Json -Compress }}
        """
        res = run_powershell(ps_log, f"event_log_size_{log.replace(' ', '_')}", timeout=8)
        data = parse_json(res.stdout) if res.ok else None
        if data and data.get("MaximumKilobytes") is not None and int(data.get("MaximumKilobytes")) < 32768:
            log_issues.append(f"{log}={data.get('MaximumKilobytes')}KB")
    if log_issues:
        findings.append(make_finding("event_log_capacity", "Windows event log capacity is low", "Monitoring", "warn", "low", "Small event logs can roll over quickly and lose security-relevant evidence.", "; ".join(log_issues), "Increase key Windows event log maximum sizes to preserve more forensic history.", True, "harden_event_log_retention", True, True, 4))
    else:
        findings.append(make_finding("event_log_capacity", "Windows event log capacity is reasonable", "Monitoring", "pass", "info", "Key Windows event logs are not below the dashboard's minimum size threshold.", "Checked Security/System/Application/Windows PowerShell log size thresholds.", "No action needed."))

    # Expanded ASR set beyond the original baseline. Avoid penalizing unsupported values harshly.
    ps_asr = r"""
    $p=Get-MpPreference -ErrorAction Stop
    [pscustomobject]@{ Ids=$p.AttackSurfaceReductionRules_Ids; Actions=$p.AttackSurfaceReductionRules_Actions } | ConvertTo-Json -Depth 5 -Compress
    """
    asr_res = run_powershell(ps_asr, "defender_expanded_asr", timeout=15)
    asr = parse_json(asr_res.stdout) if asr_res.ok else None
    if asr:
        ids = [str(x).upper() for x in ensure_list(asr.get("Ids"))]
        desired = {
            "26190899-1602-49E8-8B27-EB1D0A1CE869",
            "56A863A9-875E-4185-98A7-B882C64B5CE5",
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
            "D3E037E1-3EB8-44C8-A917-57927947596D",
            "E6DB77E5-3DF2-4CF1-B95A-636979351E5B",
        }
        missing = sorted(desired.difference(ids))
        if missing:
            findings.append(make_finding("defender_expanded_asr", "Expanded Defender ASR rules are not fully enabled", "Endpoint Protection", "warn", "medium", f"{len(missing)} additional recommended Attack Surface Reduction rule(s) are not present in Defender preferences.", f"MissingRuleIds={', '.join(missing)}", "Enable additional Microsoft Defender ASR rules that reduce script, Office, credential theft, and vulnerable-driver attack paths.", True, "enable_defender_expanded_asr", True, True, 6))
        else:
            findings.append(make_finding("defender_expanded_asr", "Expanded Defender ASR rules are enabled", "Endpoint Protection", "pass", "info", "The dashboard's expanded ASR rule set appears present.", f"RuleCount={len(ids)}", "No action needed."))


    return findings


def check_v8_extended_hardening() -> List[Finding]:
    """Expanded free hardening checks with automatic remediations.

    This module adds workstation-hardening controls while avoiding paid upgrades
    or third-party downloads. Findings are generated only from local system state.
    """
    findings: List[Finding] = []
    if not is_windows() or winreg is None:
        return [unsupported("v8_extended_hardening", "Extended Windows hardening checks", "Hardening", "Windows registry unavailable.")]

    # Microsoft Defender scanning depth and anti-evasion preferences.
    ps_defender_depth = r"""
    try {
      $p = Get-MpPreference -ErrorAction Stop
      [pscustomobject]@{
        DisableScriptScanning=$p.DisableScriptScanning
        DisableArchiveScanning=$p.DisableArchiveScanning
        DisableBlockAtFirstSeen=$p.DisableBlockAtFirstSeen
        DisableRemovableDriveScanning=$p.DisableRemovableDriveScanning
        DisableEmailScanning=$p.DisableEmailScanning
      } | ConvertTo-Json -Compress
    } catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    res = run_powershell(ps_defender_depth, "defender_deep_scanning", timeout=15)
    data = parse_json(res.stdout) if res.ok else None
    if data and not data.get("Error"):
        disabled = [k for k, v in data.items() if k.startswith("Disable") and normalize_bool(v) is True]
        if disabled:
            findings.append(make_finding("defender_deep_scanning", "Some Defender scan surfaces are disabled", "Endpoint Protection", "warn", "medium", "Microsoft Defender has one or more anti-evasion or scan-depth settings disabled.", json.dumps(data, ensure_ascii=False), "Enable script, archive, removable-drive, email, and block-at-first-seen scanning where supported.", True, "enable_defender_deep_scanning", True, True, 6))
        else:
            findings.append(make_finding("defender_deep_scanning", "Defender scan-depth settings are hardened", "Endpoint Protection", "pass", "info", "Script, archive, removable-drive, email, and block-at-first-seen settings do not appear disabled.", json.dumps(data, ensure_ascii=False), "No action needed."))
    else:
        findings.append(unsupported("defender_deep_scanning", "Defender scan-depth settings", "Endpoint Protection", str(data.get("Error") if data else res.stderr or res.stdout)))

    # Windows Firewall logging of dropped traffic for incident visibility.
    ps_fwlog = r"""
    try {
      $profiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,LogBlocked,LogAllowed,LogMaxSizeKilobytes,LogFileName
      $profiles | ConvertTo-Json -Depth 5 -Compress
    } catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    res = run_powershell(ps_fwlog, "firewall_logging", timeout=15)
    fwlogs = ensure_list(parse_json(res.stdout)) if res.ok else []
    if fwlogs and not (isinstance(fwlogs[0], dict) and fwlogs[0].get("Error")):
        weak = []
        for p in fwlogs:
            if normalize_bool(p.get("LogBlocked")) is not True or int(p.get("LogMaxSizeKilobytes") or 0) < 16384:
                weak.append(p)
        if weak:
            findings.append(make_finding("firewall_logging", "Firewall dropped-packet logging is incomplete", "Monitoring", "warn", "low", "Firewall logging helps investigate blocked inbound probes and unexpected traffic.", json.dumps(weak, ensure_ascii=False), "Enable dropped-packet logging and set a useful firewall log size for all profiles.", True, "enable_firewall_logging", True, True, 4))
        else:
            findings.append(make_finding("firewall_logging", "Firewall dropped-packet logging is enabled", "Monitoring", "pass", "info", "Firewall profiles are configured to log blocked traffic with adequate log capacity.", json.dumps(fwlogs, ensure_ascii=False), "No action needed."))

    # Optional discovery/legacy services that are unnecessary on many personal PCs.
    ps_services = r"""
    $names=@('SSDPSRV','upnphost','WebClient')
    $out=foreach($n in $names){
      $s=Get-Service -Name $n -ErrorAction SilentlyContinue
      if($s){ [pscustomobject]@{ Name=$n; Status=[int]$s.Status; StartType=[int]$s.StartType } }
      else { [pscustomobject]@{ Name=$n; Missing=$true } }
    }
    $out | ConvertTo-Json -Depth 5 -Compress
    """
    res = run_powershell(ps_services, "discovery_services", timeout=15)
    svc_data = ensure_list(parse_json(res.stdout)) if res.ok else []
    active = [s for s in svc_data if not s.get("Missing") and int(s.get("StartType") or 0) != 4]
    if active:
        findings.append(make_finding("network_discovery_services", "Legacy discovery/WebDAV services are enabled", "Network Protection", "warn", "low", "SSDP, UPnP Device Host, or WebClient can expand local attack surface when not needed.", json.dumps(active, ensure_ascii=False), "Disable SSDP, UPnP Device Host, and WebClient services unless required.", True, "disable_network_discovery_services", True, True, 4))
    elif svc_data:
        findings.append(make_finding("network_discovery_services", "Legacy discovery/WebDAV services are disabled or absent", "Network Protection", "pass", "info", "SSDP, UPnP Device Host, and WebClient are disabled or not present.", json.dumps(svc_data, ensure_ascii=False), "No action needed."))

    # NetBIOS over TCP/IP on active adapters.
    ps_netbios = r"""
    try {
      $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop |
        Select-Object Description,TcpipNetbiosOptions
      $adapters | ConvertTo-Json -Depth 5 -Compress
    } catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    res = run_powershell(ps_netbios, "netbios_over_tcpip", timeout=20)
    adapters = ensure_list(parse_json(res.stdout)) if res.ok else []
    if adapters and not (isinstance(adapters[0], dict) and adapters[0].get("Error")):
        weak = [a for a in adapters if int(a.get("TcpipNetbiosOptions") or 0) != 2]
        if weak:
            findings.append(make_finding("netbios_over_tcpip", "NetBIOS over TCP/IP is not disabled on all active adapters", "Network Protection", "warn", "low", "NetBIOS name service is a legacy local-network exposure surface.", json.dumps(weak, ensure_ascii=False), "Disable NetBIOS over TCP/IP on active network adapters unless legacy LAN name resolution is required.", True, "disable_netbios_over_tcpip", True, True, 4))
        else:
            findings.append(make_finding("netbios_over_tcpip", "NetBIOS over TCP/IP is disabled on active adapters", "Network Protection", "pass", "info", "Active adapters report TcpipNetbiosOptions=2.", json.dumps(adapters, ensure_ascii=False), "No action needed."))

    # Print Spooler hardening: only auto-disable if no physical printers are detected.
    ps_spooler = r"""
    try {
      $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
      $printers = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'PDF|XPS|OneNote|Fax' })
      [pscustomobject]@{ ServicePresent=($null -ne $svc); Status=if($svc){[int]$svc.Status}else{$null}; StartType=if($svc){[int]$svc.StartType}else{$null}; PhysicalPrinterCount=$printers.Count; Printers=@($printers | Select-Object -First 10 -ExpandProperty Name) } | ConvertTo-Json -Depth 5 -Compress
    } catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    res = run_powershell(ps_spooler, "print_spooler_exposure", timeout=20)
    sp = parse_json(res.stdout) if res.ok else None
    if sp and not sp.get("Error"):
        if sp.get("ServicePresent") and int(sp.get("StartType") or 0) != 4 and int(sp.get("PhysicalPrinterCount") or 0) == 0:
            findings.append(make_finding("print_spooler_exposure", "Print Spooler is enabled with no physical printers detected", "Network Protection", "warn", "low", "The Print Spooler has historically been a high-value attack surface. This PC does not appear to need it for physical printers.", json.dumps(sp, ensure_ascii=False), "Disable the Print Spooler only when no physical printers are configured.", True, "disable_print_spooler_if_no_physical_printers", True, True, 4))
        else:
            findings.append(make_finding("print_spooler_exposure", "Print Spooler posture is acceptable", "Network Protection", "pass", "info", "Spooler is disabled, absent, or physical printers are configured.", json.dumps(sp, ensure_ascii=False), "No action needed."))

    # Windows Installer elevation policy.
    installer_issues = []
    for root_name, root in [("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)]:
        ok, val_text, val = _reg_value_text(root, r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
        if ok and _int_or_none(val) == 1:
            installer_issues.append(f"{root_name}=1")
    if installer_issues:
        findings.append(make_finding("always_install_elevated", "AlwaysInstallElevated is enabled", "Application Hardening", "fail", "high", "AlwaysInstallElevated can allow MSI packages to run with elevated privileges and is a known privilege-escalation risk.", "; ".join(installer_issues), "Disable AlwaysInstallElevated for both machine and current-user policy hives.", True, "disable_always_install_elevated", True, True, 12))
    else:
        findings.append(make_finding("always_install_elevated", "AlwaysInstallElevated is disabled or absent", "Application Hardening", "pass", "info", "No risky AlwaysInstallElevated policy value was found in HKLM or HKCU.", "Checked HKLM/HKCU Installer policies.", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictRemoteSAM")
    if not ok or not str(val).strip():
        findings.append(make_finding("restrict_remote_sam", "Remote SAM enumeration policy is not explicitly restricted", "Identity & Access", "warn", "medium", "RestrictRemoteSAM limits which principals can remotely enumerate local accounts and groups.", f"RestrictRemoteSAM={val_text}", "Restrict remote SAM enumeration to local administrators.", True, "restrict_remote_sam", True, True, 6))
    else:
        findings.append(make_finding("restrict_remote_sam", "Remote SAM enumeration is restricted", "Identity & Access", "pass", "info", "RestrictRemoteSAM is configured.", f"RestrictRemoteSAM={val}", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM")
    if not ok or _int_or_none(val) != 1:
        findings.append(make_finding("restrict_anonymous_sam", "Anonymous SAM enumeration is not explicitly restricted", "Identity & Access", "warn", "medium", "Anonymous SAM enumeration should be blocked to reduce unauthenticated account discovery.", f"RestrictAnonymousSAM={val_text}", "Set RestrictAnonymousSAM=1.", True, "restrict_anonymous_sam", True, True, 6))
    else:
        findings.append(make_finding("restrict_anonymous_sam", "Anonymous SAM enumeration is restricted", "Identity & Access", "pass", "info", "RestrictAnonymousSAM is enabled.", f"RestrictAnonymousSAM={val}", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "DisableDomainCreds")
    if not ok or _int_or_none(val) != 1:
        findings.append(make_finding("domain_credential_storage", "Domain credential storage is not explicitly disabled", "Credential Protection", "warn", "low", "Disabling domain credential storage reduces the chance that reusable network credentials are saved locally.", f"DisableDomainCreds={val_text}", "Set DisableDomainCreds=1.", True, "disable_domain_credential_storage", True, True, 4))
    else:
        findings.append(make_finding("domain_credential_storage", "Domain credential storage is disabled", "Credential Protection", "pass", "info", "DisableDomainCreds is enabled.", f"DisableDomainCreds={val}", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DisableCAD")
    if ok and _int_or_none(val) == 1:
        findings.append(make_finding("ctrl_alt_del_logon", "Ctrl+Alt+Del secure attention sequence is disabled", "Identity & Access", "warn", "low", "Requiring Ctrl+Alt+Del before sign-in can reduce credential-prompt spoofing risk.", f"DisableCAD={val}", "Require the secure attention sequence at sign-in.", True, "enforce_ctrl_alt_del", True, True, 3))
    else:
        findings.append(make_finding("ctrl_alt_del_logon", "Ctrl+Alt+Del secure attention sequence is not disabled", "Identity & Access", "pass", "info", "DisableCAD is absent or set to require secure attention behavior.", f"DisableCAD={val_text}", "No action needed."))

    # Browser anti-phishing / credential hardening through local policy. These are free and reversible.
    ok1, t1, v1 = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "SmartScreenEnabled")
    ok2, t2, v2 = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "SmartScreenPuaEnabled")
    ok3, t3, v3 = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "PasswordManagerEnabled")
    if _int_or_none(v1) != 1 or _int_or_none(v2) != 1 or (ok3 and _int_or_none(v3) != 0):
        findings.append(make_finding("edge_browser_hardening", "Microsoft Edge browser hardening is not fully enforced", "Browser Hardening", "warn", "low", "Edge SmartScreen/PUA protection and password-manager policy are useful anti-phishing controls on shared or high-risk PCs.", f"SmartScreenEnabled={t1}; SmartScreenPuaEnabled={t2}; PasswordManagerEnabled={t3}", "Enable Edge SmartScreen and PUA checks and disable the built-in password manager by policy.", True, "enable_edge_browser_hardening", True, True, 4))
    else:
        findings.append(make_finding("edge_browser_hardening", "Microsoft Edge browser hardening is enforced", "Browser Hardening", "pass", "info", "Edge SmartScreen and PUA checks are enabled and password-manager policy is hardened.", f"SmartScreenEnabled={v1}; SmartScreenPuaEnabled={v2}; PasswordManagerEnabled={v3}", "No action needed."))

    chrome_installed = Path(os.environ.get("ProgramFiles", r"C:\Program Files"), "Google", "Chrome", "Application", "chrome.exe").exists() or Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Google", "Chrome", "Application", "chrome.exe").exists()
    ok1, t1, v1 = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome", "SafeBrowsingProtectionLevel")
    ok2, t2, v2 = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome", "PasswordManagerEnabled")
    if chrome_installed and (_int_or_none(v1) not in {1, 2} or (ok2 and _int_or_none(v2) != 0)):
        findings.append(make_finding("chrome_browser_hardening", "Google Chrome browser hardening is not fully enforced", "Browser Hardening", "warn", "low", "Chrome Safe Browsing and password-manager policy are useful anti-phishing controls on shared or high-risk PCs.", f"SafeBrowsingProtectionLevel={t1}; PasswordManagerEnabled={t2}", "Enable Chrome Safe Browsing policy and disable the built-in password manager by policy.", True, "enable_chrome_browser_hardening", True, True, 4))
    elif chrome_installed:
        findings.append(make_finding("chrome_browser_hardening", "Google Chrome browser hardening is enforced", "Browser Hardening", "pass", "info", "Chrome Safe Browsing and password-manager policies are hardened.", f"SafeBrowsingProtectionLevel={v1}; PasswordManagerEnabled={v2}", "No action needed."))
    else:
        findings.append(make_finding("chrome_browser_hardening", "Google Chrome not detected", "Browser Hardening", "info", "info", "Chrome executable was not found in standard Program Files locations.", "Chrome not detected.", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate")
    if ok and _int_or_none(val) == 1:
        findings.append(make_finding("windows_auto_update_policy", "Windows automatic updates are disabled by policy", "Patch Management", "fail", "high", "NoAutoUpdate=1 prevents normal automatic update behavior.", f"NoAutoUpdate={val}", "Re-enable automatic updates by policy.", True, "ensure_windows_update_auto", True, True, 12))
    else:
        findings.append(make_finding("windows_auto_update_policy", "Windows automatic updates are not disabled by policy", "Patch Management", "pass", "info", "No policy value was found that disables automatic updates.", f"NoAutoUpdate={val_text}", "No action needed."))

    ok, val_text, val = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "EnableLMHOSTS")
    if ok and _int_or_none(val) == 1:
        findings.append(make_finding("lmhosts_lookup", "LMHOSTS lookup is enabled", "Network Protection", "warn", "low", "LMHOSTS is a legacy NetBIOS name-resolution mechanism that is usually unnecessary on modern personal PCs.", f"EnableLMHOSTS={val}", "Disable LMHOSTS lookup.", True, "disable_lmhosts_lookup", True, True, 3))
    else:
        findings.append(make_finding("lmhosts_lookup", "LMHOSTS lookup is disabled or absent", "Network Protection", "pass", "info", "LMHOSTS lookup does not appear enabled.", f"EnableLMHOSTS={val_text}", "No action needed."))

    # Screen-lock baseline for unattended PC risk.
    ok_secure, sec_text, sec_val = _reg_value_text(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "ScreenSaverIsSecure")
    ok_timeout, timeout_text, timeout_val = _reg_value_text(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "ScreenSaveTimeOut")
    timeout_num = _int_or_none(timeout_val) if ok_timeout else None
    if str(sec_val) != "1" or timeout_num is None or timeout_num <= 0 or timeout_num > 900:
        findings.append(make_finding("screen_lock_timeout", "Automatic screen lock is not tightly configured", "User Safety", "warn", "low", "A short secure screen-lock timeout reduces risk from unattended sessions.", f"ScreenSaverIsSecure={sec_text}; ScreenSaveTimeOut={timeout_text}", "Require secure screen lock within 15 minutes for the current user.", True, "enforce_screen_lock_timeout", True, True, 3))
    else:
        findings.append(make_finding("screen_lock_timeout", "Automatic screen lock baseline is configured", "User Safety", "pass", "info", "Current-user screen lock is secure and set to 15 minutes or less.", f"ScreenSaverIsSecure={sec_val}; ScreenSaveTimeOut={timeout_val}", "No action needed."))

    return findings



def check_v9_enterprise_hardening() -> List[Finding]:
    """More enterprise-style, free, allowlisted Windows hardening checks.

    These controls are implemented as deterministic checks with matching remediations
    so the mapping from finding to fix action remains easy to audit. The dashboard does
    not install software, download tools, or recommend paid upgrades.
    """
    findings: List[Finding] = []
    if not is_windows() or winreg is None:
        return [unsupported("v9_enterprise_hardening", "Enterprise hardening checks", "Hardening", "Windows registry unavailable.")]

    def reg_check(root: Any, path: str, name: str, desired: Any, finding_id: str, title_bad: str,
                  title_good: str, category: str, severity: str, summary_bad: str, recommendation: str,
                  action: str, requires_admin: bool = True, impact: int = 3, value_kind: str = "dword") -> None:
        ok, text, val = _reg_value_text(root, path, name)
        good = False
        if value_kind == "string":
            good = ok and str(val).lower() == str(desired).lower()
        else:
            good = ok and _int_or_none(val) == int(desired)
        if good:
            findings.append(make_finding(finding_id, title_good, category, "pass", "info", f"{name} is set to the desired hardening value.", f"{name}={val}", "No action needed."))
        else:
            findings.append(make_finding(finding_id, title_bad, category, "warn", severity, summary_bad, f"{name}={text}", recommendation, True, action, True, requires_admin, impact))

    reg_check(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "ScreenSaverIsSecure", "1", "screen_lock_secure", "Secure screen saver lock is not enforced", "Secure screen saver lock is enforced", "User Safety", "low", "The current user session may not require a password when the screen saver ends.", "Require password after unlock and configure the screen lock baseline.", "enforce_screen_lock_timeout", False, 2, "string")
    # Timeout is checked separately so the loose setting is shown directly.
    ok, timeout_text, timeout_val = _reg_value_text(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "ScreenSaveTimeOut")
    timeout_num = _int_or_none(timeout_val) if ok else None
    if timeout_num is None or timeout_num <= 0 or timeout_num > 900:
        findings.append(make_finding("screen_lock_timeout_v9", "Screen lock timeout is longer than 15 minutes or unset", "User Safety", "warn", "low", "A short lock timeout reduces unattended-session risk.", f"ScreenSaveTimeOut={timeout_text}", "Set the current-user screen lock timeout to 15 minutes.", True, "enforce_screen_lock_timeout", True, False, 2))
    else:
        findings.append(make_finding("screen_lock_timeout_v9", "Screen lock timeout is 15 minutes or less", "User Safety", "pass", "info", "Current-user screen lock timeout is within the dashboard baseline.", f"ScreenSaveTimeOut={timeout_val}", "No action needed."))

    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocation", 1, "location_tracking", "Windows location tracking is not disabled by policy", "Windows location tracking is disabled by policy", "Privacy Hardening", "low", "Location access can expose sensitive user context on shared or high-risk machines.", "Disable Windows location tracking by policy.", "disable_location_tracking", True, 2)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0, "activity_history_publish", "Activity history publishing is not disabled by policy", "Activity history publishing is disabled", "Privacy Hardening", "low", "Activity history can sync usage metadata across Microsoft experiences.", "Disable activity history publishing/uploading.", "disable_activity_history", True, 2)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 1, "diagnostic_telemetry", "Diagnostic telemetry is above the required-data baseline or unset", "Diagnostic telemetry is limited by policy", "Privacy Hardening", "low", "Limiting diagnostic telemetry reduces unnecessary data exposure while preserving Windows Update support.", "Set Windows diagnostic telemetry to the lowest generally supported level for Home/Pro clients.", "reduce_diagnostics_telemetry", True, 2)
    reg_check(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0, "tailored_experiences", "Tailored experiences may use diagnostic data", "Tailored experiences from diagnostic data are disabled", "Privacy Hardening", "low", "Tailored experiences can use diagnostic data for personalization.", "Disable tailored experiences from diagnostic data.", "disable_tailored_experiences", False, 2)
    reg_check(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackProgs", 0, "app_launch_tracking", "App launch tracking is enabled or unset", "App launch tracking is disabled", "Privacy Hardening", "low", "App/document tracking can expose usage patterns on a shared PC.", "Disable app launch and recent document tracking.", "disable_app_launch_tracking", False, 2)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", 1, "lock_screen_camera", "Lock-screen camera access is not disabled by policy", "Lock-screen camera access is disabled", "User Safety", "low", "Disabling lock-screen camera access reduces pre-authentication exposure.", "Disable camera access from the lock screen.", "disable_lock_screen_camera", True, 2)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "DisableLockScreenAppNotifications", 1, "lock_screen_notifications", "Lock-screen app notifications are not disabled by policy", "Lock-screen app notifications are disabled", "User Safety", "low", "Lock-screen notifications can disclose sensitive information before sign-in.", "Disable lock-screen app notifications.", "disable_lock_screen_notifications", True, 2)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled", 0, "windows_script_host", "Windows Script Host is enabled or unset", "Windows Script Host is disabled", "Script Safety", "medium", "Windows Script Host can execute VBScript/JScript payloads commonly abused in phishing and malware chains.", "Disable Windows Script Host unless legacy scripts require it.", "disable_windows_script_host", True, 5)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DisableIPSourceRouting", 2, "ip_source_routing", "IP source routing is not fully disabled", "IP source routing is disabled", "Network Protection", "low", "Source routing is legacy network behavior that should be disabled on clients.", "Disable IPv4/IPv6 source routing and ICMP redirects.", "harden_tcpip_stack", True, 3)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "EnableICMPRedirect", 0, "icmp_redirects", "ICMP redirects are enabled or unset", "ICMP redirects are disabled", "Network Protection", "low", "ICMP redirects can be abused for route manipulation on hostile networks.", "Disable ICMP redirect acceptance.", "harden_tcpip_stack", True, 3)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "SynAttackProtect", 1, "syn_attack_protect", "TCP SYN attack protection is not explicitly enabled", "TCP SYN attack protection is enabled", "Network Protection", "low", "SYN attack protection is a lightweight TCP/IP hardening control.", "Enable TCP SYN attack protection.", "harden_tcpip_stack", True, 2)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\cdrom", "AutoRun", 0, "cdrom_autorun", "CD/DVD AutoRun is enabled or unset", "CD/DVD AutoRun is disabled", "User Safety", "low", "Disabling optical-media AutoRun reduces removable-media execution risk.", "Disable CD/DVD AutoRun.", "disable_cdrom_autorun", True, 2)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "Disabled", 1, "windows_error_reporting", "Windows Error Reporting is not disabled by policy", "Windows Error Reporting upload prompts are disabled", "Privacy Hardening", "low", "Crash reports can contain metadata or snippets that are not needed for a hardened personal baseline.", "Disable Windows Error Reporting upload prompts by policy.", "disable_windows_error_reporting", True, 2)
    reg_check(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1, "consumer_experiences", "Windows consumer suggestions are not disabled by policy", "Windows consumer suggestions are disabled", "Privacy Hardening", "low", "Consumer suggestions and silent app recommendations add unnecessary content and noise to a hardened workstation.", "Disable Windows consumer experiences and app suggestions.", "disable_consumer_experiences", True, 2)

    # Defender scheduled scan check.
    ps_def_sched = r"""
    try {
      $p = Get-MpPreference -ErrorAction Stop
      [pscustomobject]@{ ScanScheduleDay=$p.ScanScheduleDay; ScanScheduleTime=[string]$p.ScanScheduleTime; RandomizeScheduleTaskTimes=$p.RandomizeScheduleTaskTimes } | ConvertTo-Json -Compress
    } catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    sched_res = run_powershell(ps_def_sched, "defender_scheduled_scan", timeout=20)
    sched = parse_json(sched_res.stdout) if sched_res.ok else None
    if sched and not sched.get("Error"):
        day = str(sched.get("ScanScheduleDay", ""))
        if day in {"8", "Never", "NeverSchedule"}:
            findings.append(make_finding("defender_scheduled_scan", "Defender scheduled scan appears disabled", "Endpoint Protection", "warn", "low", "A scheduled scan provides recurring baseline malware coverage even when quick scans are missed.", json.dumps(sched), "Configure a recurring Defender scheduled scan.", True, "enable_defender_scheduled_scan", True, True, 3))
        else:
            findings.append(make_finding("defender_scheduled_scan", "Defender scheduled scan is configured", "Endpoint Protection", "pass", "info", "Defender returned a scheduled scan configuration.", json.dumps(sched), "No action needed."))
    else:
        findings.append(make_finding("defender_scheduled_scan", "Defender scheduled scan state could not be confirmed", "Endpoint Protection", "info", "info", "Defender did not return scheduled scan settings.", sched_res.stderr or sched_res.stdout, "No automatic action taken for this informational check."))

    # Expanded audit policy check.
    ps_audit = r"""
    $subs=@('Credential Validation','Account Lockout','User Account Management','Security Group Management','Audit Policy Change','Authentication Policy Change','Special Logon')
    $out=foreach($s in $subs){
      $raw=(auditpol /get /subcategory:$s /r 2>$null) -join "`n"
      [pscustomobject]@{ Subcategory=$s; Raw=$raw; HasSuccess=($raw -match 'Success'); HasFailure=($raw -match 'Failure') }
    }
    $out | ConvertTo-Json -Depth 4 -Compress
    """
    audit_res = run_powershell(ps_audit, "expanded_audit_policy", timeout=25)
    audit = ensure_list(parse_json(audit_res.stdout)) if audit_res.ok else []
    weak = [a for a in audit if not (a.get("HasSuccess") and a.get("HasFailure"))]
    if audit and weak:
        findings.append(make_finding("expanded_audit_policy", "Expanded Windows audit policy is incomplete", "Monitoring", "warn", "low", f"{len(weak)} monitored audit subcategory setting(s) lack Success and Failure coverage.", json.dumps(weak[:8], ensure_ascii=False), "Enable Success and Failure auditing for key identity/security policy events.", True, "enable_expanded_audit_policy", True, True, 3))
    elif audit:
        findings.append(make_finding("expanded_audit_policy", "Expanded Windows audit policy is enabled", "Monitoring", "pass", "info", "Key identity and policy audit subcategories include Success and Failure coverage.", json.dumps(audit[:8], ensure_ascii=False), "No action needed."))
    else:
        findings.append(make_finding("expanded_audit_policy", "Expanded audit policy could not be confirmed", "Monitoring", "info", "info", "auditpol did not return detailed subcategory data.", audit_res.stderr or audit_res.stdout, "No automatic action taken for this informational check."))

    # Service checks: warn only if installed and enabled/running.
    ps_services = r"""
    $names=@('sshd','W3SVC','WAS','FDResPub','fdPHost')
    $out=foreach($n in $names){
      $s=Get-Service -Name $n -ErrorAction SilentlyContinue
      if($s){ [pscustomobject]@{ Name=$n; Status=[string]$s.Status; StartType=[string]$s.StartType } }
      else { [pscustomobject]@{ Name=$n; Missing=$true } }
    }
    $out | ConvertTo-Json -Depth 4 -Compress
    """
    svc_res = run_powershell(ps_services, "v9_service_surface", timeout=20)
    services = ensure_list(parse_json(svc_res.stdout)) if svc_res.ok else []
    svc_by_name = {str(x.get("Name")): x for x in services}
    def service_risky(name: str) -> bool:
        s = svc_by_name.get(name, {})
        return not s.get("Missing") and str(s.get("StartType", "")).lower() not in {"disabled", "4"}
    if service_risky("sshd"):
        findings.append(make_finding("openssh_server_service", "OpenSSH Server service is installed and enabled", "Remote Access", "warn", "medium", "An enabled SSH server increases remote-access attack surface if not intentionally administered.", json.dumps(svc_by_name.get("sshd")), "Disable the OpenSSH Server service unless this PC intentionally accepts SSH connections.", True, "disable_openssh_server", True, True, 5))
    else:
        findings.append(make_finding("openssh_server_service", "OpenSSH Server service is disabled or absent", "Remote Access", "pass", "info", "OpenSSH Server is not enabled.", json.dumps(svc_by_name.get("sshd", {"Missing": True})), "No action needed."))
    if service_risky("W3SVC") or service_risky("WAS"):
        findings.append(make_finding("iis_services", "IIS web server services are enabled", "Network Exposure", "warn", "medium", "Local web server services expose HTTP application surface and should be disabled if not intentionally used.", json.dumps([svc_by_name.get("W3SVC"), svc_by_name.get("WAS")], ensure_ascii=False), "Disable IIS web services unless this PC intentionally hosts websites.", True, "disable_iis_services", True, True, 5))
    else:
        findings.append(make_finding("iis_services", "IIS web server services are disabled or absent", "Network Exposure", "pass", "info", "IIS web services are not enabled.", json.dumps([svc_by_name.get("W3SVC", {"Missing": True}), svc_by_name.get("WAS", {"Missing": True})], ensure_ascii=False), "No action needed."))
    if service_risky("FDResPub") or service_risky("fdPHost"):
        findings.append(make_finding("function_discovery_services", "Function Discovery publishing services are enabled", "Network Protection", "warn", "low", "Function Discovery services can advertise this PC on local networks.", json.dumps([svc_by_name.get("FDResPub"), svc_by_name.get("fdPHost")], ensure_ascii=False), "Disable Function Discovery publishing services unless LAN discovery is required.", True, "disable_function_discovery_services", True, True, 3))
    else:
        findings.append(make_finding("function_discovery_services", "Function Discovery publishing services are disabled or absent", "Network Protection", "pass", "info", "Function Discovery services are not enabled.", json.dumps([svc_by_name.get("FDResPub", {"Missing": True}), svc_by_name.get("fdPHost", {"Missing": True})], ensure_ascii=False), "No action needed."))

    # IPv6 transition technologies check.
    ps_tunnel = r"""
    $teredo=(netsh interface teredo show state 2>$null) -join "`n"
    $isatap=(netsh interface isatap show state 2>$null) -join "`n"
    $six=(netsh interface 6to4 show state 2>$null) -join "`n"
    [pscustomobject]@{ Teredo=$teredo; ISATAP=$isatap; SixToFour=$six } | ConvertTo-Json -Compress
    """
    tun_res = run_powershell(ps_tunnel, "transition_tunnel_state", timeout=20)
    tun = parse_json(tun_res.stdout) if tun_res.ok else {}
    tun_text = json.dumps(tun, ensure_ascii=False)

    def transition_enabled(raw: Any) -> bool:
        text = str(raw or "").lower()
        # Avoid false positives from phrases such as "Client Refresh Interval".
        # Teredo disabled commonly still prints "client" words and an offline state.
        if re.search(r"(?mi)^\s*type\s*:\s*disabled\s*$", text):
            return False
        if re.search(r"(?mi)^\s*state\s*:\s*(disabled|offline)\s*$", text):
            return False
        if re.search(r"(?mi)^\s*type\s*:\s*(client|enterpriseclient)\s*$", text):
            return True
        if re.search(r"(?mi)^\s*state\s*:\s*(enabled|qualified|dormant|probe)\s*$", text):
            return True
        return False

    tunnel_is_enabled = any(transition_enabled(v) for v in (tun or {}).values())
    if tunnel_is_enabled:
        findings.append(make_finding("transition_tunneling", "IPv6 transition tunneling appears enabled", "Network Protection", "warn", "low", "Teredo, ISATAP, or 6to4 tunneling can bypass expected network boundaries on some clients.", tun_text[:1000], "Disable Teredo, ISATAP, and 6to4 tunneling unless explicitly required.", True, "disable_teredo_tunneling", True, True, 3))
    else:
        findings.append(make_finding("transition_tunneling", "IPv6 transition tunneling is disabled or unavailable", "Network Protection", "pass", "info", "Teredo, ISATAP, and 6to4 did not appear enabled.", tun_text[:1000], "No action needed."))

    return findings


def check_v10_deep_hardening() -> List[Finding]:
    """Deep local-client hardening checks with automatic free remediations.

    v10 intentionally focuses on settings that can be inspected and changed locally
    without paid Windows edition upgrades or third-party software. Each warning maps
    to a single allowlisted remediation action so the UI can offer both individual
    Fix buttons and Fix all coverage.
    """
    findings: List[Finding] = []
    if not is_windows() or winreg is None:
        return [unsupported("v10_deep_hardening", "Deep local-client hardening checks", "Hardening", "Windows registry unavailable.")]

    def reg_int(root: Any, path: str, name: str, desired: int, finding_id: str, title_bad: str,
                title_good: str, category: str, severity: str, summary_bad: str, recommendation: str,
                action: str, requires_admin: bool = True, impact: int = 2, missing_is_ok: bool = False,
                pass_on_min: Optional[int] = None) -> None:
        ok, text, val = _reg_value_text(root, path, name)
        num = _int_or_none(val) if ok else None
        good = False
        if not ok and missing_is_ok:
            good = True
        elif pass_on_min is not None:
            good = num is not None and num >= pass_on_min
        else:
            good = num == desired
        if good:
            findings.append(make_finding(finding_id, title_good, category, "pass", "info", f"{name} is at the dashboard baseline or safely absent.", f"{name}={text}", "No action needed."))
        else:
            findings.append(make_finding(finding_id, title_bad, category, "warn", severity, summary_bad, f"{name}={text}", recommendation, True, action, True, requires_admin, impact))

    def reg_multi_empty(root: Any, path: str, name: str, finding_id: str, title_bad: str, title_good: str,
                        category: str, action: str, impact: int = 3) -> None:
        ok, value, msg = registry_get(root, path, name)
        entries = []
        if ok:
            if isinstance(value, (list, tuple)):
                entries = [str(x) for x in value if str(x).strip()]
            elif str(value).strip():
                entries = [str(value)]
        if (not ok) or not entries:
            findings.append(make_finding(finding_id, title_good, category, "pass", "info", f"{name} is empty or absent.", f"{name}={entries if ok else msg}", "No action needed."))
        else:
            findings.append(make_finding(finding_id, title_bad, category, "warn", "low", "Null-session entries can expose legacy unauthenticated SMB surfaces.", f"{name}={entries}", "Clear null-session shares and pipes.", True, action, True, True, impact))

    # WinRM client/service authentication and shell controls.
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "AllowBasic", 0,
            "winrm_client_basic", "WinRM Client Basic authentication is not disabled by policy", "WinRM Client Basic authentication is disabled", "Remote Access", "low", "Basic authentication should not be available for WinRM client connections.", "Disable WinRM Basic authentication in client and service policy.", "disable_winrm_basic_auth", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowBasic", 0,
            "winrm_service_basic", "WinRM Service Basic authentication is not disabled by policy", "WinRM Service Basic authentication is disabled", "Remote Access", "low", "Basic authentication should not be available for WinRM service connections.", "Disable WinRM Basic authentication in client and service policy.", "disable_winrm_basic_auth", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "AllowUnencryptedTraffic", 0,
            "winrm_client_unencrypted", "WinRM Client unencrypted traffic is not disabled by policy", "WinRM Client unencrypted traffic is disabled", "Remote Access", "low", "WinRM should reject unencrypted client transport.", "Disable WinRM unencrypted traffic policies.", "disable_winrm_unencrypted", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencryptedTraffic", 0,
            "winrm_service_unencrypted", "WinRM Service unencrypted traffic is not disabled by policy", "WinRM Service unencrypted traffic is disabled", "Remote Access", "low", "WinRM should reject unencrypted service transport.", "Disable WinRM unencrypted traffic policies.", "disable_winrm_unencrypted", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS", "AllowRemoteShellAccess", 0,
            "winrm_remote_shell", "WinRM remote shell access is not disabled by policy", "WinRM remote shell access is disabled", "Remote Access", "low", "Remote shell access increases administrative attack surface on a personal PC.", "Disable WinRM remote shell access.", "disable_winrm_remote_shell", True, 2)

    # RDP remains hardened even if the service is disabled, because firewall/services can be re-enabled later.
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1,
            "rdp_nla_required", "RDP Network Level Authentication is not explicitly required", "RDP Network Level Authentication is required", "Remote Access", "low", "If RDP is ever enabled, NLA should be required before session creation.", "Require RDP Network Level Authentication.", "harden_rdp_nla", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "SecurityLayer", 2,
            "rdp_tls_security_layer", "RDP TLS security layer is not explicitly required", "RDP TLS security layer is required", "Remote Access", "low", "If RDP is ever enabled, it should use the strongest standard security layer.", "Require the RDP TLS security layer.", "harden_rdp_nla", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDisableCdm", 1,
            "rdp_drive_redirection", "RDP drive redirection is not disabled by policy", "RDP drive redirection is disabled", "Remote Access", "low", "Drive redirection can move data between local and remote systems.", "Disable RDP drive, device, and clipboard redirection.", "disable_rdp_redirection", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDisableClip", 1,
            "rdp_clipboard_redirection", "RDP clipboard redirection is not disabled by policy", "RDP clipboard redirection is disabled", "Remote Access", "low", "Clipboard redirection can expose secrets across RDP sessions.", "Disable RDP drive, device, and clipboard redirection.", "disable_rdp_redirection", True, 2)

    # SMB/Lanman legacy exposure.
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "AutoShareWks", 0,
            "admin_shares", "Automatic administrative shares are enabled or unset", "Automatic administrative shares are disabled", "Network Protection", "low", "ADMIN$/C$ style administrative shares are unnecessary on most standalone personal PCs.", "Disable automatic administrative shares.", "disable_admin_shares", True, 2)
    reg_multi_empty(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "NullSessionPipes", "null_session_pipes", "Null-session pipes are configured", "Null-session pipes are empty or absent", "Network Protection", "clear_null_sessions", 2)
    reg_multi_empty(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "NullSessionShares", "null_session_shares", "Null-session shares are configured", "Null-session shares are empty or absent", "Network Protection", "clear_null_sessions", 2)

    # Attachment/download and user tracking controls.
    reg_int(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments", "ScanWithAntiVirus", 3,
            "attachment_manager_scan", "Attachment Manager antivirus scanning is not enforced", "Attachment Manager antivirus scanning is enforced", "User Safety", "low", "Downloaded attachments should be handed to antivirus scanning where Windows supports it.", "Require Attachment Manager antivirus scanning.", "enable_attachment_manager_scan", False, 2)
    reg_int(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoRecentDocsHistory", 1,
            "recent_docs_history", "Recent document history is not disabled", "Recent document history is disabled", "Privacy Hardening", "low", "Recent document history can disclose sensitive file activity on shared systems.", "Disable recent document history.", "disable_recent_docs_history", False, 2)
    reg_int(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0,
            "start_bing_search", "Start/Search web suggestions are not disabled", "Start/Search web suggestions are disabled", "Privacy Hardening", "low", "Start menu searches can send query context to web services.", "Disable Start/Search web suggestions.", "disable_web_search_in_start", False, 2)
    reg_int(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1,
            "search_box_suggestions", "Search box suggestions are not disabled by policy", "Search box suggestions are disabled by policy", "Privacy Hardening", "low", "Search suggestions can disclose local search intent to web-connected experiences.", "Disable Search box suggestions.", "disable_web_search_in_start", False, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", 0,
            "cortana_policy", "Cortana is not disabled by policy", "Cortana is disabled by policy", "Privacy Hardening", "low", "Cortana/assistant search integrations are unnecessary on a hardened workstation baseline.", "Disable Cortana/search assistant behavior by policy.", "disable_web_search_in_start", True, 2)

    # Telemetry, feedback, personalization, and content delivery.
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DoNotShowFeedbackNotifications", 1,
            "feedback_notifications", "Windows feedback notifications are not disabled by policy", "Windows feedback notifications are disabled", "Privacy Hardening", "low", "Feedback prompts add unnecessary data-collection prompts and noise.", "Disable Windows feedback notifications.", "disable_feedback_notifications", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\SQMClient\Windows", "CEIPEnable", 0,
            "ceip", "Customer Experience Improvement Program is not disabled by policy", "Customer Experience Improvement Program is disabled", "Privacy Hardening", "low", "CEIP is not needed for a hardened local workstation baseline.", "Disable CEIP policy values.", "disable_ceip", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "AITEnable", 0,
            "app_telemetry", "Application telemetry is not disabled by policy", "Application telemetry is disabled", "Privacy Hardening", "low", "Application telemetry and compatibility inventory can expose installed-application metadata.", "Disable application telemetry and inventory collection.", "disable_app_telemetry", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisableInventory", 1,
            "app_inventory", "Application inventory collection is not disabled by policy", "Application inventory collection is disabled", "Privacy Hardening", "low", "Inventory collection is unnecessary for a privacy-focused local baseline.", "Disable application telemetry and inventory collection.", "disable_app_telemetry", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectAllowedOEM", 0,
            "wifi_sense_auto_connect", "Wi-Fi Sense/OEM auto-connect behavior is not disabled", "Wi-Fi Sense/OEM auto-connect behavior is disabled", "Network Protection", "low", "Automatic Wi-Fi connection behavior can create unwanted network exposure.", "Disable Wi-Fi Sense/OEM auto-connect behavior.", "disable_wifi_sense", True, 2)
    reg_int(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "ContentDeliveryAllowed", 0,
            "content_delivery", "Windows content delivery suggestions are enabled or unset", "Windows content delivery suggestions are disabled", "Privacy Hardening", "low", "Content delivery and suggestion mechanisms add unnecessary cloud-driven content to the shell.", "Disable Windows content delivery suggestions.", "disable_content_delivery", False, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\InputPersonalization", "AllowInputPersonalization", 0,
            "input_personalization", "Input personalization is not disabled by policy", "Input personalization is disabled", "Privacy Hardening", "low", "Input personalization can collect typing/inking patterns.", "Disable input personalization data collection.", "disable_input_personalization", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1,
            "implicit_text_collection", "Implicit text collection is not restricted", "Implicit text collection is restricted", "Privacy Hardening", "low", "Text personalization collection is not needed on a hardened baseline.", "Restrict implicit text and ink collection.", "disable_input_personalization", True, 2)

    # UAC/exploit mitigation and RPC hardening.
    ok_c, text_c, val_c = _reg_value_text(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
    consent = _int_or_none(val_c) if ok_c else None
    if consent is None or consent == 0:
        findings.append(make_finding("uac_consent_behavior", "UAC admin consent prompt behavior is weak or unset", "Device Hardening", "warn", "low", "Administrators should receive a consent/credential prompt instead of silently elevating.", f"ConsentPromptBehaviorAdmin={text_c}", "Enforce safer UAC prompt behavior.", True, "enforce_uac_prompt_behavior", True, True, 2))
    else:
        findings.append(make_finding("uac_consent_behavior", "UAC admin consent prompt behavior is configured", "Device Hardening", "pass", "info", "Administrator elevation prompts are not configured for silent elevation.", f"ConsentPromptBehaviorAdmin={text_c}", "No action needed."))
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableInstallerDetection", 1,
            "uac_installer_detection", "UAC installer detection is not enabled", "UAC installer detection is enabled", "Device Hardening", "low", "Installer detection helps catch setup programs that require elevation.", "Enable UAC installer detection.", "enforce_uac_prompt_behavior", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "RestrictRemoteClients", 1,
            "rpc_restrict_remote_clients", "RPC remote client restriction is not enabled", "RPC remote client restriction is enabled", "Network Protection", "low", "Unauthenticated RPC access should be restricted on client workstations.", "Restrict unauthenticated RPC clients.", "restrict_rpc_clients", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "EnableAuthEpResolution", 1,
            "rpc_auth_endpoint_resolution", "RPC authenticated endpoint resolution is not enabled", "RPC authenticated endpoint resolution is enabled", "Network Protection", "low", "Authenticated RPC endpoint resolution reduces unauthenticated enumeration surface.", "Enable authenticated RPC endpoint resolution.", "restrict_rpc_clients", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager", "SafeDllSearchMode", 1,
            "safe_dll_search", "Safe DLL search order is not explicitly enabled", "Safe DLL search order is enabled", "Application Hardening", "low", "Safe DLL search order reduces DLL preloading/hijacking risk.", "Enable SafeDllSearchMode.", "enable_safe_dll_search", True, 2)
    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "DisableExceptionChainValidation", 0,
            "sehop", "SEH overwrite protection is not explicitly enabled", "SEH overwrite protection is enabled", "Application Hardening", "low", "SEH overwrite protection helps mitigate older memory-corruption exploitation paths.", "Enable SEH overwrite protection.", "enable_sehop", True, 2)

    # Additional firewall/service exposure checks.
    def firewall_group_check(group: str, finding_id: str, title_bad: str, title_good: str, action: str, impact: int = 2) -> None:
        ps = f"$r=@(Get-NetFirewallRule -DisplayGroup '{group}' -ErrorAction SilentlyContinue | Where-Object {{ $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' }}); [pscustomobject]@{{ Count=$r.Count; Names=@($r | Select-Object -ExpandProperty DisplayName) }} | ConvertTo-Json -Compress"
        res = run_powershell(ps, finding_id, timeout=20)
        data = parse_json(res.stdout) if res.ok else None
        count = int(data.get("Count", 0)) if isinstance(data, dict) and str(data.get("Count", "0")).isdigit() else 0
        evidence = json.dumps(data if data is not None else {"Error": res.stderr or res.stdout}, ensure_ascii=False)
        if count > 0:
            findings.append(make_finding(finding_id, title_bad, "Network Protection", "warn", "low", f"{count} enabled inbound firewall rule(s) were found in the {group} group.", evidence, "Disable this inbound firewall group unless explicitly needed.", True, action, True, True, impact))
        else:
            findings.append(make_finding(finding_id, title_good, "Network Protection", "pass", "info", f"No enabled inbound firewall rules were found in the {group} group.", evidence, "No action needed."))

    firewall_group_check("Remote Desktop", "rdp_firewall_rules", "Remote Desktop inbound firewall rules are enabled", "Remote Desktop inbound firewall rules are disabled", "disable_remote_desktop_firewall_group", 2)
    firewall_group_check("Remote Assistance", "remote_assistance_firewall_rules", "Remote Assistance inbound firewall rules are enabled", "Remote Assistance inbound firewall rules are disabled", "disable_remote_assistance_firewall_group", 2)

    ps_services = r"""
    $names=@('WMPNetworkSvc','XboxNetApiSvc','XblAuthManager','XblGameSave','XboxGipSvc','lfsvc')
    $out=foreach($n in $names){ $s=Get-Service -Name $n -ErrorAction SilentlyContinue; if($s){ [pscustomobject]@{ Name=$s.Name; Status=[string]$s.Status; StartType=[string]$s.StartType } } else { [pscustomobject]@{ Name=$n; Missing=$true } } }
    $out | ConvertTo-Json -Compress
    """
    svc_res = run_powershell(ps_services, "v10_services", timeout=25)
    svc_items = ensure_list(parse_json(svc_res.stdout)) if svc_res.ok else []
    by_name = {str(x.get("Name")): x for x in svc_items if isinstance(x, dict)}

    def svc_enabled(name: str) -> bool:
        x = by_name.get(name) or {}
        return not x.get("Missing") and str(x.get("StartType", "")).lower() != "disabled"

    if svc_enabled("WMPNetworkSvc"):
        findings.append(make_finding("media_sharing_service", "Windows Media Player sharing service is enabled", "Network Protection", "warn", "low", "Media sharing service can advertise or share local media on networks.", json.dumps(by_name.get("WMPNetworkSvc"), ensure_ascii=False), "Disable Windows Media Player sharing service unless media sharing is required.", True, "disable_media_sharing_service", True, True, 2))
    else:
        findings.append(make_finding("media_sharing_service", "Windows Media Player sharing service is disabled or absent", "Network Protection", "pass", "info", "Media sharing service is not enabled.", json.dumps(by_name.get("WMPNetworkSvc", {"Missing": True}), ensure_ascii=False), "No action needed."))
    xbox_enabled = [n for n in ("XboxNetApiSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc") if svc_enabled(n)]
    if xbox_enabled:
        findings.append(make_finding("xbox_services", "Xbox networking/game services are enabled", "Network Protection", "warn", "low", "Xbox networking services are unnecessary on a hardened non-gaming workstation baseline.", json.dumps([by_name.get(n) for n in xbox_enabled], ensure_ascii=False), "Disable Xbox networking/game services if this PC does not need them.", True, "disable_xbox_services", True, True, 2))
    else:
        findings.append(make_finding("xbox_services", "Xbox networking/game services are disabled or absent", "Network Protection", "pass", "info", "Xbox services are not enabled.", json.dumps([by_name.get(n, {"Name": n, "Missing": True}) for n in ("XboxNetApiSvc", "XblAuthManager", "XblGameSave", "XboxGipSvc")], ensure_ascii=False), "No action needed."))
    if svc_enabled("lfsvc"):
        findings.append(make_finding("geolocation_service", "Geolocation service is enabled", "Privacy Hardening", "warn", "low", "The geolocation service is unnecessary if location tracking is disabled by policy.", json.dumps(by_name.get("lfsvc"), ensure_ascii=False), "Disable Geolocation service.", True, "disable_geolocation_service", True, True, 2))
    else:
        findings.append(make_finding("geolocation_service", "Geolocation service is disabled or absent", "Privacy Hardening", "pass", "info", "Geolocation service is not enabled.", json.dumps(by_name.get("lfsvc", {"Missing": True}), ensure_ascii=False), "No action needed."))

    reg_int(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Installer", "DisableUserInstalls", 1,
            "windows_installer_user_installs", "Windows Installer user installs are not disabled by policy", "Windows Installer user installs are disabled by policy", "Application Hardening", "low", "Per-user MSI installs can increase persistence and software-control risk on a hardened workstation.", "Harden Windows Installer policy.", "harden_windows_installer", True, 2)

    return findings

def gather_system_info() -> Dict[str, Any]:
    info = windows_build()
    # Uptime via PowerShell on Windows.
    ps = r"""
    try {
      $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
      $boot = $os.LastBootUpTime
      [pscustomobject]@{ LastBoot=$boot.ToString('s'); UptimeHours=[int]((Get-Date)-$boot).TotalHours } | ConvertTo-Json -Compress
    } catch { [pscustomobject]@{ Error=$_.Exception.Message } | ConvertTo-Json -Compress }
    """
    res = run_powershell(ps, "system_uptime", timeout=10)
    if res.ok:
        uptime = parse_json(res.stdout)
        if uptime and not uptime.get("Error"):
            info.update({"last_boot": uptime.get("LastBoot"), "uptime_hours": uptime.get("UptimeHours")})
    return info


def run_scan() -> Dict[str, Any]:
    start = time.perf_counter()
    findings: List[Finding] = []

    if not is_windows():
        findings.append(make_finding(
            "platform_windows",
            "Windows-specific scanner running on non-Windows OS",
            "System",
            "unsupported",
            "info",
            "This dashboard is designed to assess Windows PCs. Some checks will be unavailable here.",
            f"platform={platform.platform()}",
            "Run on the target Windows PC for full assessment.",
        ))
    else:
        findings.append(make_finding(
            "platform_windows",
            "Windows platform detected",
            "System",
            "pass",
            "info",
            "The scanner is running on a Windows-compatible platform.",
            f"platform={platform.platform()}",
            "No action needed.",
        ))

    scanners: List[Callable[[], List[Finding]]] = [
        check_firewall,
        check_defender,
        check_installed_antivirus,
        check_windows_update,
        check_bitlocker_secureboot_tpm,
        check_remote_access,
        check_legacy_protocols_services,
        check_identity_accounts,
        check_windows_security_settings,
        check_credential_network_hardening,
        check_security_service_baselines,
        check_logging_hardening,
        check_additional_hardening,
        check_v8_extended_hardening,
        check_v9_enterprise_hardening,
        check_v10_deep_hardening,
        check_network_exposure,
        check_hosts_startup_audit,
    ]

    for scanner in scanners:
        try:
            findings.extend(scanner())
        except Exception as exc:
            findings.append(make_finding(
                f"scanner_error_{scanner.__name__}",
                f"Scanner error: {scanner.__name__}",
                "Scanner Reliability",
                "unsupported",
                "info",
                "A scanner module failed safely without stopping the full assessment.",
                f"{type(exc).__name__}: {exc}",
                "Review the local audit log and scanner code for this module.",
            ))
            AuditLogger.write("scanner_error", {"scanner": scanner.__name__, "error": str(exc), "traceback": traceback.format_exc(limit=3)})

    public_findings = [f.to_public() for f in findings]
    score = calculate_score(public_findings)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    categories: Dict[str, Dict[str, int]] = {}
    for f in public_findings:
        cat = f["category"]
        categories.setdefault(cat, {"pass": 0, "warn": 0, "fail": 0, "info": 0, "unsupported": 0})
        categories[cat][f["status"]] = categories[cat].get(f["status"], 0) + 1

    result = {
        "app": {"name": APP_NAME, "version": APP_VERSION},
        "scan": {"timestamp_utc": now_iso(), "duration_ms": elapsed_ms, "admin": is_admin()},
        "system": gather_system_info(),
        "score": score,
        "summary": {
            "total": len(public_findings),
            "pass": sum(1 for f in public_findings if f["status"] == "pass"),
            "warn": sum(1 for f in public_findings if f["status"] == "warn"),
            "fail": sum(1 for f in public_findings if f["status"] == "fail"),
            "unsupported": sum(1 for f in public_findings if f["status"] == "unsupported"),
            "fixable": sum(1 for f in public_findings if f.get("fixable")),
            "fix_all_available": sum(1 for f in public_findings if f.get("fixable") and f.get("safe_for_fix_all") and f["status"] in {"fail", "warn"}),
        },
        "categories": categories,
        "findings": public_findings,
    }
    AuditLogger.write("scan_completed", {"duration_ms": elapsed_ms, "score": score, "summary": result["summary"]})
    return result


def calculate_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_impact = 0
    critical = high = medium = low = 0
    for f in findings:
        if f.get("status") not in {"fail", "warn"}:
            continue
        impact = int(f.get("score_impact") or SEVERITY_IMPACT.get(f.get("severity"), 0))
        total_impact += impact
        sev = f.get("severity")
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            medium += 1
        elif sev == "low":
            low += 1
    score = max(0, 100 - min(100, total_impact))
    if score >= 90:
        grade = "Excellent"
    elif score >= 75:
        grade = "Good"
    elif score >= 60:
        grade = "Fair"
    elif score >= 40:
        grade = "Poor"
    else:
        grade = "Critical"
    return {
        "value": score,
        "grade": grade,
        "deductions": total_impact,
        "severity_counts": {"critical": critical, "high": high, "medium": medium, "low": low},
    }


@dataclass(frozen=True)
class FixDefinition:
    action: str
    title: str
    requires_admin: bool
    safe_for_fix_all: bool
    command_kind: str  # powershell, cmd, or python
    command: List[str] | str
    timeout: int = 60
    restart_note: Optional[str] = None


def ps_fix(script: str, name: str, timeout: int = 60) -> CommandResult:
    return run_powershell(script, command_name=name, timeout=timeout)


def cmd_fix(args: List[str], name: str, timeout: int = 60) -> CommandResult:
    return run_command(args, command_name=name, timeout=timeout)


def open_windows_target(target: str, action: str) -> CommandResult:
    """Open a local Windows settings/control-panel target without taking system-changing action."""
    if not is_windows():
        return CommandResult(False, "", "This action is available only on Windows.", 127, action)
    try:
        if target.endswith(".msc"):
            subprocess.Popen([target], shell=False, creationflags=(subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0))
        elif target.lower().startswith("control.exe"):
            parts = target.split()
            subprocess.Popen(parts, shell=False, creationflags=(subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0))
        else:
            os.startfile(target)  # type: ignore[attr-defined]
        return CommandResult(True, f"Opened {target}", "", 0, action)
    except Exception as exc:
        return CommandResult(False, "", f"Unable to open {target}: {exc}", 1, action)


def python_fix(action: str) -> CommandResult:
    """Execute selected remediation using native Python APIs where possible.

    Using winreg for user-scope registry changes avoids PowerShell registry-provider
    edge cases and makes failures easier to diagnose.
    """
    if winreg is None:
        return CommandResult(False, "", "Windows registry is unavailable.", 127, action)
    if action == "enable_autorun_protection":
        return registry_set_dword(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun",
            255,
        )
    if action == "enable_file_extensions":
        return registry_set_dword(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "HideFileExt",
            0,
        )
    if action == "enable_uac":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
            1,
        )
    if action == "disable_remote_assistance":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
            "fAllowToGetHelp",
            0,
        )
    if action == "enable_lsa_protection":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL",
            1,
        )
    if action == "disable_rdp":
        reg_result = registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
            1,
        )
        fw_result = ps_fix("Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue", "disable_rdp_firewall", 30)
        # Firewall group may not exist on every Windows edition, so a successful registry change is sufficient.
        if reg_result.ok and not fw_result.ok:
            return CommandResult(True, reg_result.stdout + "\nRemote Desktop registry setting changed; firewall rule update was unavailable or unnecessary.", "", 0, action)
        return combine_results(action, [reg_result, fw_result])
    if action == "enable_memory_integrity":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled",
            1,
        )
    if action == "enable_smartscreen":
        return combine_results(action, [
            registry_set_string(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Warn"),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\AppHost", "EnableWebContentEvaluation", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1),
        ])
    if action == "disable_insecure_guest_auth":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "AllowInsecureGuestAuth",
            0,
        )
    if action == "enable_restrict_anonymous":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RestrictAnonymous",
            1,
        )
    if action == "enable_wdigest_protection":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential",
            0,
        )
    if action == "set_lm_compatibility_level":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LmCompatibilityLevel",
            5,
        )
    if action == "enable_blank_password_restriction":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LimitBlankPasswordUse",
            1,
        )
    if action == "enable_smb_signing":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnableSecuritySignature", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSecuritySignature", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 1),
        ])
    if action == "disable_llmnr":
        return registry_set_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "EnableMulticast",
            0,
        )
    if action == "enable_process_creation_auditing":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled", 1),
            run_command(["auditpol", "/set", "/subcategory:Process Creation", "/success:enable"], "enable_process_creation_auditing", timeout=15),
        ])
    if action == "enable_powershell_logging":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", 1),
            registry_set_string(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames", "*", "*"),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableInvocationHeader", 1),
        ])
    if action == "enforce_uac_secure_desktop":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5),
        ])
    if action == "disable_auto_admin_logon":
        return combine_results(action, [
            registry_set_string(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "0"),
            registry_set_string(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword", ""),
        ])
    if action == "enable_no_lm_hash":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash", 1)
    if action == "limit_cached_logons":
        return registry_set_string(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount", "10")
    if action == "disable_password_reveal":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\CredUI", "DisablePasswordReveal", 1)
    if action == "harden_tls_defaults":
        results: List[CommandResult] = []
        for proto in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]:
            for role in ["Client", "Server"]:
                path = rf"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{proto}\{role}"
                results.append(registry_set_dword(winreg.HKEY_LOCAL_MACHINE, path, "Enabled", 0))
                results.append(registry_set_dword(winreg.HKEY_LOCAL_MACHINE, path, "DisabledByDefault", 1))
        for proto in ["TLS 1.2", "TLS 1.3"]:
            for role in ["Client", "Server"]:
                path = rf"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{proto}\{role}"
                results.append(registry_set_dword(winreg.HKEY_LOCAL_MACHINE, path, "Enabled", 1))
                results.append(registry_set_dword(winreg.HKEY_LOCAL_MACHINE, path, "DisabledByDefault", 0))
        return combine_results(action, results)
    if action == "block_office_internet_macros":
        results: List[CommandResult] = []
        for root in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            for app in ["Word", "Excel", "PowerPoint"]:
                path = rf"Software\Policies\Microsoft\Office\16.0\{app}\Security"
                results.append(registry_set_dword(root, path, "blockcontentexecutionfrominternet", 1))
        return combine_results(action, results)
    if action == "disable_delivery_optimization_internet_peer":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config", "DODownloadMode", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization", "DODownloadMode", 0),
        ])
    if action == "disable_advertising_id":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1),
        ])
    if action == "disable_clipboard_cloud":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard", "EnableClipboardHistory", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard", "EnableCloudClipboard", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "AllowClipboardHistory", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "AllowCrossDeviceClipboard", 0),
        ])
    if action == "harden_autoplay_policy":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", "DisableAutoplay", 1),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255),
        ])
    if action == "disable_web_search_in_start":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Search", "CortanaConsent", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1),
        ])
    if action == "schedule_restart_60":
        return run_command(["shutdown", "/r", "/t", "60", "/c", "Cybersecurity Dashboard scheduled restart to complete security changes."], "schedule_restart_60", timeout=10)
    if action == "enable_firewall_stealth_mode":
        # Registry fallback for Windows builds where Set-NetFirewallProfile lacks
        # -DisableUnicastResponsesToMulticastBroadcast.
        results = []
        for profile in ["DomainProfile", "StandardProfile", "PublicProfile"]:
            results.append(registry_set_dword(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile}",
                "DisableUnicastResponsesToMulticastBroadcast",
                1,
            ))
        return combine_results(action, results)
    if action == "disable_always_install_elevated":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", 0),
        ])
    if action == "restrict_remote_sam":
        return registry_set_string(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RestrictRemoteSAM",
            "O:BAG:BAD:(A;;RC;;;BA)",
        )
    if action == "restrict_anonymous_sam":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM", 1)
    if action == "disable_domain_credential_storage":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "DisableDomainCreds", 1)
    if action == "enforce_ctrl_alt_del":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DisableCAD", 0)
    if action == "enable_edge_browser_hardening":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "SmartScreenEnabled", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "SmartScreenPuaEnabled", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "PasswordManagerEnabled", 0),
        ])
    if action == "enable_chrome_browser_hardening":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome", "SafeBrowsingProtectionLevel", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome", "PasswordManagerEnabled", 0),
        ])
    if action == "ensure_windows_update_auto":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", 0)
    if action == "disable_lmhosts_lookup":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "EnableLMHOSTS", 0)
    if action == "enforce_screen_lock_timeout":
        return combine_results(action, [
            registry_set_string(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "ScreenSaveActive", "1"),
            registry_set_string(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "ScreenSaverIsSecure", "1"),
            registry_set_string(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "ScreenSaveTimeOut", "900"),
        ])
    if action == "disable_location_tracking":
        return combine_results(action, [
            registry_set_string(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", "Deny"),
            registry_set_string(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", "Deny"),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocation", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableWindowsLocationProvider", 1),
        ])
    if action == "disable_activity_history":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0),
        ])
    if action == "reduce_diagnostics_telemetry":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 1)
    if action == "disable_tailored_experiences":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableTailoredExperiencesWithDiagnosticData", 1),
        ])
    if action == "disable_app_launch_tracking":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackProgs", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackDocs", 0),
        ])
    if action == "disable_lock_screen_camera":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", 1)
    if action == "disable_lock_screen_notifications":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "DisableLockScreenAppNotifications", 1)
    if action == "disable_windows_script_host":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled", 0),
        ])
    if action == "harden_tcpip_stack":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DisableIPSourceRouting", 2),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisableIPSourceRouting", 2),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "EnableICMPRedirect", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "SynAttackProtect", 1),
        ])
    if action == "disable_cdrom_autorun":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\cdrom", "AutoRun", 0)
    if action == "disable_windows_error_reporting":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\Windows Error Reporting", "Disabled", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "Disabled", 1),
        ])
    if action == "disable_consumer_experiences":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableSoftLanding", 1),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338389Enabled", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338388Enabled", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SilentInstalledAppsEnabled", 0),
        ])
    if action == "disable_winrm_basic_auth":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "AllowBasic", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowBasic", 0),
        ])
    if action == "disable_winrm_unencrypted":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", "AllowUnencryptedTraffic", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencryptedTraffic", 0),
        ])
    if action == "disable_winrm_remote_shell":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS", "AllowRemoteShellAccess", 0)
    if action == "harden_rdp_nla":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "SecurityLayer", 2),
        ])
    if action == "disable_rdp_redirection":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDisableCdm", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDisableClip", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDisablePNPRedir", 1),
        ])
    if action == "disable_admin_shares":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "AutoShareWks", 0)
    if action == "clear_null_sessions":
        return combine_results(action, [
            registry_set_multi_string(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "NullSessionPipes", []),
            registry_set_multi_string(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "NullSessionShares", []),
        ])
    if action == "enable_attachment_manager_scan":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments", "ScanWithAntiVirus", 3),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments", "ScanWithAntiVirus", 3),
        ])
    if action == "disable_recent_docs_history":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoRecentDocsHistory", 1),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackDocs", 0),
        ])
    if action == "disable_feedback_notifications":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Siuf\Rules", "PeriodInNanoSeconds", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DoNotShowFeedbackNotifications", 1),
        ])
    if action == "disable_ceip":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\SQMClient\Windows", "CEIPEnable", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\SQMClient\Windows", "CEIPEnable", 0),
        ])
    if action == "disable_app_telemetry":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "AITEnable", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisableInventory", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisablePCA", 1),
        ])
    if action == "disable_wifi_sense":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectAllowedOEM", 0)
    if action == "disable_content_delivery":
        vals = [
            "ContentDeliveryAllowed", "FeatureManagementEnabled", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled",
            "PreInstalledAppsEverEnabled", "RotatingLockScreenEnabled", "RotatingLockScreenOverlayEnabled",
            "SilentInstalledAppsEnabled", "SoftLandingEnabled", "SubscribedContent-310093Enabled",
            "SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled",
        ]
        return combine_results(action, [registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", v, 0) for v in vals])
    if action == "disable_input_personalization":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\InputPersonalization", "AllowInputPersonalization", 0),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", 1),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1),
        ])
    if action == "enforce_uac_prompt_behavior":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorUser", 3),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableInstallerDetection", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ValidateAdminCodeSignatures", 0),
        ])
    if action == "restrict_rpc_clients":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "RestrictRemoteClients", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "EnableAuthEpResolution", 1),
        ])
    if action == "enable_safe_dll_search":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager", "SafeDllSearchMode", 1)
    if action == "enable_sehop":
        return registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "DisableExceptionChainValidation", 0)
    if action == "harden_windows_installer":
        return combine_results(action, [
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Installer", "DisableUserInstalls", 1),
            registry_set_dword(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", 0),
            registry_set_dword(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", 0),
        ])
    if action == "clean_suspicious_hosts":
        hosts_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
        try:
            raw = hosts_path.read_text(encoding="utf-8", errors="replace").splitlines()
            suspicious_words = ("update", "defender", "microsoft", "windowsupdate", "security", "antivirus")
            kept = []
            removed = []
            for line in raw:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and any(w in stripped.lower() for w in suspicious_words):
                    removed.append(line)
                else:
                    kept.append(line)
            if not removed:
                return CommandResult(True, "No suspicious hosts entries found.", "", 0, action)
            backup = hosts_path.with_name("hosts.cyberdashboard.bak")
            backup.write_text("\n".join(raw) + "\n", encoding="utf-8")
            hosts_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
            return CommandResult(True, f"Removed {len(removed)} suspicious hosts line(s). Backup saved to {backup}", "", 0, action)
        except PermissionError as exc:
            return CommandResult(False, "", f"Permission denied modifying hosts file: {exc}", 5, action)
        except Exception as exc:
            return CommandResult(False, "", f"Unable to clean hosts file: {exc}", 1, action)
    return CommandResult(False, "", "No Python remediation handler is defined for this action.", 1, action)


FIXES: Dict[str, FixDefinition] = {
    "enable_firewall": FixDefinition("enable_firewall", "Enable Windows Firewall profiles", True, True, "powershell", "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop"),
    "harden_firewall_default_inbound": FixDefinition("harden_firewall_default_inbound", "Set firewall default inbound policy to Block", True, True, "powershell", "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -ErrorAction Stop"),
    "disable_network_discovery_firewall_group": FixDefinition("disable_network_discovery_firewall_group", "Disable Network Discovery inbound firewall rules", True, True, "powershell", "Get-NetFirewallRule -DisplayGroup 'Network Discovery' -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' } | Disable-NetFirewallRule -ErrorAction Stop"),
    "disable_file_printer_sharing_firewall_group": FixDefinition("disable_file_printer_sharing_firewall_group", "Disable File and Printer Sharing inbound firewall rules", True, True, "powershell", "Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' } | Disable-NetFirewallRule -ErrorAction Stop"),
    "enable_defender_realtime": FixDefinition("enable_defender_realtime", "Enable Defender real-time protection", True, True, "powershell", "Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -ErrorAction Stop"),
    "enable_defender_cloud": FixDefinition("enable_defender_cloud", "Enable Defender cloud protection", True, True, "powershell", "Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop"),
    "enable_defender_pua": FixDefinition("enable_defender_pua", "Enable Defender PUA protection", True, True, "powershell", "Set-MpPreference -PUAProtection Enabled -ErrorAction Stop"),
    "update_defender_signatures": FixDefinition("update_defender_signatures", "Update Defender signatures", True, True, "powershell", "Update-MpSignature -ErrorAction Stop", 180),
    "run_defender_quick_scan": FixDefinition("run_defender_quick_scan", "Run Microsoft Defender quick scan", True, True, "powershell", "Start-MpScan -ScanType QuickScan -ErrorAction Stop", 3600),
    "enable_controlled_folder_access": FixDefinition("enable_controlled_folder_access", "Enable Controlled Folder Access", True, True, "powershell", "Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop"),
    "enable_defender_network_protection": FixDefinition("enable_defender_network_protection", "Enable Defender Network Protection", True, True, "powershell", "Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop"),
    "enable_defender_asr_baseline": FixDefinition("enable_defender_asr_baseline", "Enable Defender ASR baseline", True, True, "powershell", "$ids=@('D4F940AB-401B-4EFC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899','BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550','9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2','C1DB55AB-C21A-4637-BB3F-A12568109D35'); foreach($id in $ids){ Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop }"),
    "remove_all_defender_exclusions": FixDefinition("remove_all_defender_exclusions", "Remove all Microsoft Defender exclusions", True, True, "powershell", "$p=Get-MpPreference -ErrorAction Stop; foreach($x in @($p.ExclusionPath)){ if($x){ Remove-MpPreference -ExclusionPath $x -ErrorAction Stop } }; foreach($x in @($p.ExclusionProcess)){ if($x){ Remove-MpPreference -ExclusionProcess $x -ErrorAction Stop } }; foreach($x in @($p.ExclusionExtension)){ if($x){ Remove-MpPreference -ExclusionExtension $x -ErrorAction Stop } }"),
    "enable_smartscreen": FixDefinition("enable_smartscreen", "Enable Windows SmartScreen/app reputation checks", True, True, "python", "enable_smartscreen"),
    "disable_rdp": FixDefinition("disable_rdp", "Disable Remote Desktop", True, True, "python", "disable_rdp"),
    "disable_smb1": FixDefinition("disable_smb1", "Disable SMBv1", True, True, "powershell", "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null", 180, "Restart may be required to fully complete SMBv1 removal."),
    "enable_uac": FixDefinition("enable_uac", "Enable User Account Control", True, True, "python", "enable_uac", 60, "Restart may be required for UAC changes."),
    "disable_guest": FixDefinition("disable_guest", "Disable built-in Guest account", True, True, "cmd", ["net", "user", "Guest", "/active:no"]),
    "disable_builtin_administrator": FixDefinition("disable_builtin_administrator", "Disable built-in Administrator account", True, True, "cmd", ["net", "user", "Administrator", "/active:no"]),
    "enable_autorun_protection": FixDefinition("enable_autorun_protection", "Disable AutoRun for all drive types", False, True, "python", "enable_autorun_protection"),
    "disable_winrm": FixDefinition("disable_winrm", "Disable WinRM service", True, True, "powershell", "Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue; Set-Service -Name WinRM -StartupType Disabled -ErrorAction Stop"),
    "disable_remote_registry": FixDefinition("disable_remote_registry", "Disable Remote Registry service", True, True, "powershell", "Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue; Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction Stop"),
    "enable_file_extensions": FixDefinition("enable_file_extensions", "Show known file extensions", False, True, "python", "enable_file_extensions"),
    "disable_remote_assistance": FixDefinition("disable_remote_assistance", "Disable Remote Assistance", True, True, "python", "disable_remote_assistance"),
    "enable_lsa_protection": FixDefinition("enable_lsa_protection", "Enable LSA protection", True, True, "python", "enable_lsa_protection", 60, "Restart is required for LSA protection."),
    "enable_memory_integrity": FixDefinition("enable_memory_integrity", "Enable Memory Integrity / HVCI", True, True, "python", "enable_memory_integrity", 60, "Restart is required and incompatible drivers may still prevent Memory Integrity from enabling."),
    "set_machine_password_policy": FixDefinition("set_machine_password_policy", "Set stronger local password policy", True, True, "cmd", ["net", "accounts", "/minpwlen:12", "/lockoutthreshold:10"]),
    "set_powershell_remote_signed": FixDefinition("set_powershell_remote_signed", "Set PowerShell policy to RemoteSigned for current user", False, True, "powershell", "Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction Stop"),
    "disable_powershell_v2": FixDefinition("disable_powershell_v2", "Disable PowerShell 2.0 optional feature", True, True, "powershell", "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null", 180, "Restart may be required."),
    "disable_insecure_guest_auth": FixDefinition("disable_insecure_guest_auth", "Disable insecure SMB guest authentication", True, True, "python", "disable_insecure_guest_auth"),
    "enable_restrict_anonymous": FixDefinition("enable_restrict_anonymous", "Restrict anonymous enumeration", True, True, "python", "enable_restrict_anonymous"),
    "enable_wdigest_protection": FixDefinition("enable_wdigest_protection", "Disable WDigest credential caching", True, True, "python", "enable_wdigest_protection", 60, "Restart or sign-out may be required."),
    "set_lm_compatibility_level": FixDefinition("set_lm_compatibility_level", "Harden LM/NTLM compatibility level", True, True, "python", "set_lm_compatibility_level"),
    "enable_blank_password_restriction": FixDefinition("enable_blank_password_restriction", "Restrict blank-password network logons", True, True, "python", "enable_blank_password_restriction"),
    "enable_smb_signing": FixDefinition("enable_smb_signing", "Enable and require SMB signing", True, True, "python", "enable_smb_signing", 60, "Restart may be required for SMB policy changes."),
    "disable_llmnr": FixDefinition("disable_llmnr", "Disable LLMNR multicast name resolution", True, True, "python", "disable_llmnr"),
    "enable_windows_update_services": FixDefinition("enable_windows_update_services", "Enable Windows Update support services", True, True, "powershell", "Set-Service -Name wuauserv -StartupType Manual -ErrorAction SilentlyContinue; Set-Service -Name BITS -StartupType Manual -ErrorAction SilentlyContinue; Start-Service -Name BITS -ErrorAction SilentlyContinue; Start-Service -Name wuauserv -ErrorAction SilentlyContinue; Write-Output 'Windows Update support services enabled or started where available.'"),
    "start_security_services": FixDefinition("start_security_services", "Start Windows Security services", True, True, "powershell", "foreach($n in @('wscsvc','SecurityHealthService','WinDefend')){ try { Set-Service -Name $n -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name $n -ErrorAction SilentlyContinue } catch {} }; Write-Output 'Security services checked and started where Windows allowed.'"),
    "block_risky_inbound_ports": FixDefinition("block_risky_inbound_ports", "Add firewall blocks for risky inbound services", True, True, "powershell", "$ports=@(21,23,135,139,445,3389,5985,5986); $base='CyberDashboard - Block risky inbound TCP services'; Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like ($base+'*') } | Remove-NetFirewallRule -ErrorAction SilentlyContinue; foreach($p in $ports){ New-NetFirewallRule -DisplayName ($base+' - '+$p) -Direction Inbound -Action Block -Protocol TCP -LocalPort $p -Profile Any -ErrorAction Stop | Out-Null }; Write-Output ('Blocked inbound TCP ports: '+($ports -join ', '))", 60),
    "run_windows_update_scan": FixDefinition("run_windows_update_scan", "Start Windows Update scan", True, True, "powershell", "Start-Process -FilePath usoclient.exe -ArgumentList StartScan -WindowStyle Hidden -ErrorAction SilentlyContinue; Start-Process -FilePath usoclient.exe -ArgumentList StartInstall -WindowStyle Hidden -ErrorAction SilentlyContinue", 30),
    "schedule_restart_60": FixDefinition("schedule_restart_60", "Schedule restart in 60 seconds", True, True, "python", "schedule_restart_60", 10, "Restart scheduled. Run 'shutdown /a' quickly from Command Prompt to cancel."),
    "enable_bitlocker_safely": FixDefinition("enable_bitlocker_safely", "Enable BitLocker with recovery-key file", True, True, "powershell", "$drive=$env:SystemDrive; $dir=Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'CyberDashboard-RecoveryKeys'; New-Item -ItemType Directory -Force -Path $dir | Out-Null; $before=(manage-bde -protectors -get $drive 2>$null) -join [Environment]::NewLine; $add=(manage-bde -protectors -add $drive -RecoveryPassword 2>&1) -join [Environment]::NewLine; $after=(manage-bde -protectors -get $drive 2>&1) -join [Environment]::NewLine; $combined=$before+[Environment]::NewLine+$add+[Environment]::NewLine+$after; $matches=[regex]::Matches($combined,'(\\d{6}-){7}\\d{6}'); if($matches.Count -lt 1){ throw 'Could not confirm recovery password from manage-bde output. BitLocker was not enabled.' }; $key=$matches[$matches.Count-1].Value; $file=Join-Path $dir ('BitLocker-RecoveryKey-'+$env:COMPUTERNAME+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt'); Set-Content -Path $file -Value ('BitLocker recovery password for '+$env:COMPUTERNAME+' '+$drive+[Environment]::NewLine+$key) -Encoding UTF8; manage-bde -on $drive -UsedSpaceOnly -SkipHardwareTest | Out-Null; Write-Output ('Recovery key saved to '+$file+'; BitLocker enablement started.')", 240, "Encryption may continue in the background. Keep the recovery-key file safe."),
    "disable_telnet_service": FixDefinition("disable_telnet_service", "Disable Telnet Server service", True, True, "powershell", "Stop-Service -Name TlntSvr -Force -ErrorAction SilentlyContinue; Set-Service -Name TlntSvr -StartupType Disabled -ErrorAction Stop"),
    "disable_ftp_service": FixDefinition("disable_ftp_service", "Disable Microsoft FTP Service", True, True, "powershell", "Stop-Service -Name FTPSVC -Force -ErrorAction SilentlyContinue; Set-Service -Name FTPSVC -StartupType Disabled -ErrorAction Stop"),
    "disable_snmp_service": FixDefinition("disable_snmp_service", "Disable SNMP Service", True, True, "powershell", "Stop-Service -Name SNMP -Force -ErrorAction SilentlyContinue; Set-Service -Name SNMP -StartupType Disabled -ErrorAction Stop"),
    "clean_suspicious_hosts": FixDefinition("clean_suspicious_hosts", "Back up and clean suspicious hosts entries", True, True, "python", "clean_suspicious_hosts"),
    "disable_icmp_echo_firewall_rules": FixDefinition("disable_icmp_echo_firewall_rules", "Disable inbound ICMP echo firewall rules", True, True, "powershell", "$rules=Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue; foreach($r in $rules){ try { $pf=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop; if($pf.Protocol -in @('ICMPv4','ICMPv6')){ $r | Disable-NetFirewallRule -ErrorAction Stop } } catch {} }; Write-Output 'Inbound ICMP echo allow rules disabled where present.'", 60),
    "disable_remote_management_firewall_rules": FixDefinition("disable_remote_management_firewall_rules", "Disable remote-management inbound firewall groups", True, True, "powershell", "foreach($g in @('Core Networking Diagnostics','Remote Event Log Management','Remote Service Management','Windows Management Instrumentation (WMI)','Windows Remote Management')){ Get-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' } | Disable-NetFirewallRule -ErrorAction SilentlyContinue }; Write-Output 'Remote-management firewall groups disabled where present.'", 60),
    "enable_firewall_stealth_mode": FixDefinition("enable_firewall_stealth_mode", "Enable firewall stealth response hardening", True, True, "python", "enable_firewall_stealth_mode", 60),
    "enforce_uac_secure_desktop": FixDefinition("enforce_uac_secure_desktop", "Enforce UAC secure-desktop elevation prompts", True, True, "python", "enforce_uac_secure_desktop", 60, "Sign-out or restart may be required for all UAC policy changes."),
    "disable_auto_admin_logon": FixDefinition("disable_auto_admin_logon", "Disable AutoAdminLogon and clear stored password", True, True, "python", "disable_auto_admin_logon"),
    "enable_no_lm_hash": FixDefinition("enable_no_lm_hash", "Prevent LAN Manager hash storage", True, True, "python", "enable_no_lm_hash", 60, "Password changes after this setting will no longer create LM hashes."),
    "limit_cached_logons": FixDefinition("limit_cached_logons", "Limit cached domain logons", True, True, "python", "limit_cached_logons"),
    "disable_password_reveal": FixDefinition("disable_password_reveal", "Disable password reveal button", True, True, "python", "disable_password_reveal"),
    "harden_tls_defaults": FixDefinition("harden_tls_defaults", "Harden Windows SCHANNEL TLS defaults", True, True, "python", "harden_tls_defaults", 60, "Restart may be required for all TLS/SCHANNEL changes."),
    "block_office_internet_macros": FixDefinition("block_office_internet_macros", "Block Office macros from internet documents", True, True, "python", "block_office_internet_macros"),
    "disable_delivery_optimization_internet_peer": FixDefinition("disable_delivery_optimization_internet_peer", "Disable Delivery Optimization internet peer mode", True, True, "python", "disable_delivery_optimization_internet_peer"),
    "disable_advertising_id": FixDefinition("disable_advertising_id", "Disable Windows advertising ID", False, True, "python", "disable_advertising_id"),
    "disable_clipboard_cloud": FixDefinition("disable_clipboard_cloud", "Disable clipboard history and cloud clipboard", False, True, "python", "disable_clipboard_cloud"),
    "harden_autoplay_policy": FixDefinition("harden_autoplay_policy", "Disable AutoPlay and reinforce AutoRun policy", False, True, "python", "harden_autoplay_policy"),
    "disable_web_search_in_start": FixDefinition("disable_web_search_in_start", "Disable Start/Search web suggestions", False, True, "python", "disable_web_search_in_start"),
    "harden_event_log_retention": FixDefinition("harden_event_log_retention", "Increase Windows event log capacity", True, True, "powershell", "wevtutil sl Security /ms:67108864; wevtutil sl System /ms:33554432; wevtutil sl Application /ms:33554432; wevtutil sl 'Windows PowerShell' /ms:33554432; Write-Output 'Event log maximum sizes increased.'", 60),
    "enable_defender_expanded_asr": FixDefinition("enable_defender_expanded_asr", "Enable expanded Defender ASR hardening", True, True, "powershell", "$desired=@('26190899-1602-49E8-8B27-EB1D0A1CE869','56A863A9-875E-4185-98A7-B882C64B5CE5','5BEB7EFE-FD9A-4556-801D-275E5FFC04CC','75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84','D3E037E1-3EB8-44C8-A917-57927947596D','E6DB77E5-3DF2-4CF1-B95A-636979351E5B'); foreach($id in $desired){ try { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop } catch {} }; Write-Output 'Expanded ASR rules enabled where supported.'", 90),
    "enable_defender_deep_scanning": FixDefinition("enable_defender_deep_scanning", "Enable Defender deep scanning controls", True, True, "powershell", "try { Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue } catch {}; try { Set-MpPreference -DisableArchiveScanning $false -ErrorAction SilentlyContinue } catch {}; try { Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue } catch {}; try { Set-MpPreference -DisableRemovableDriveScanning $false -ErrorAction SilentlyContinue } catch {}; try { Set-MpPreference -DisableEmailScanning $false -ErrorAction SilentlyContinue } catch {}; Write-Output 'Defender deep scanning preferences enabled where supported.'", 90),
    "enable_firewall_logging": FixDefinition("enable_firewall_logging", "Enable Windows Firewall dropped-packet logging", True, True, "powershell", "Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogAllowed False -LogMaxSizeKilobytes 16384 -ErrorAction Stop; Write-Output 'Firewall blocked-packet logging enabled for all profiles.'", 60),
    "disable_network_discovery_services": FixDefinition("disable_network_discovery_services", "Disable SSDP, UPnP Device Host, and WebClient services", True, True, "powershell", "foreach($n in @('SSDPSRV','upnphost','WebClient')){ try { Stop-Service -Name $n -Force -ErrorAction SilentlyContinue; Set-Service -Name $n -StartupType Disabled -ErrorAction SilentlyContinue } catch {} }; Write-Output 'Discovery/WebDAV services disabled where present.'", 60),
    "disable_netbios_over_tcpip": FixDefinition("disable_netbios_over_tcpip", "Disable NetBIOS over TCP/IP on active adapters", True, True, "powershell", "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"IPEnabled=True\" | ForEach-Object { try { Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null } catch {} }; Write-Output 'NetBIOS over TCP/IP disabled where supported.'", 90, "Network adapter restart or reconnect may be required."),
    "disable_print_spooler_if_no_physical_printers": FixDefinition("disable_print_spooler_if_no_physical_printers", "Disable Print Spooler when no physical printers are configured", True, True, "powershell", "$printers=@(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'PDF|XPS|OneNote|Fax' }); if($printers.Count -gt 0){ Write-Output 'Physical printers detected. Spooler was not disabled.'; exit 0 }; Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue; Set-Service -Name Spooler -StartupType Disabled -ErrorAction Stop; Write-Output 'Print Spooler disabled because no physical printers were detected.'", 90),
    "disable_always_install_elevated": FixDefinition("disable_always_install_elevated", "Disable AlwaysInstallElevated MSI policy", True, True, "python", "disable_always_install_elevated"),
    "restrict_remote_sam": FixDefinition("restrict_remote_sam", "Restrict remote SAM enumeration", True, True, "python", "restrict_remote_sam"),
    "restrict_anonymous_sam": FixDefinition("restrict_anonymous_sam", "Restrict anonymous SAM enumeration", True, True, "python", "restrict_anonymous_sam"),
    "disable_domain_credential_storage": FixDefinition("disable_domain_credential_storage", "Disable storage of domain credentials", True, True, "python", "disable_domain_credential_storage"),
    "enforce_ctrl_alt_del": FixDefinition("enforce_ctrl_alt_del", "Require Ctrl+Alt+Del secure attention at sign-in", True, True, "python", "enforce_ctrl_alt_del", 60, "Sign-out or restart may be required."),
    "enable_edge_browser_hardening": FixDefinition("enable_edge_browser_hardening", "Enable Microsoft Edge browser hardening policies", True, True, "python", "enable_edge_browser_hardening"),
    "enable_chrome_browser_hardening": FixDefinition("enable_chrome_browser_hardening", "Enable Google Chrome browser hardening policies", True, True, "python", "enable_chrome_browser_hardening"),
    "ensure_windows_update_auto": FixDefinition("ensure_windows_update_auto", "Ensure Windows automatic updates are not disabled", True, True, "python", "ensure_windows_update_auto"),
    "disable_lmhosts_lookup": FixDefinition("disable_lmhosts_lookup", "Disable LMHOSTS lookup", True, True, "python", "disable_lmhosts_lookup", 60, "Network adapter restart or reconnect may be required."),
    "enforce_screen_lock_timeout": FixDefinition("enforce_screen_lock_timeout", "Require secure screen lock within 15 minutes", False, True, "python", "enforce_screen_lock_timeout"),
    "enable_failed_logon_audit": FixDefinition("enable_failed_logon_audit", "Enable failed logon auditing", True, True, "cmd", ["auditpol", "/set", "/subcategory:Logon", "/failure:enable"]),
    "enable_process_creation_auditing": FixDefinition("enable_process_creation_auditing", "Enable process creation auditing", True, True, "python", "enable_process_creation_auditing"),
    "enable_powershell_logging": FixDefinition("enable_powershell_logging", "Enable PowerShell security logging", True, True, "python", "enable_powershell_logging"),
    "disable_location_tracking": FixDefinition("disable_location_tracking", "Disable Windows location tracking", True, True, "python", "disable_location_tracking"),
    "disable_activity_history": FixDefinition("disable_activity_history", "Disable Windows activity history sync", True, True, "python", "disable_activity_history"),
    "reduce_diagnostics_telemetry": FixDefinition("reduce_diagnostics_telemetry", "Limit Windows diagnostic telemetry to required data", True, True, "python", "reduce_diagnostics_telemetry"),
    "disable_tailored_experiences": FixDefinition("disable_tailored_experiences", "Disable tailored experiences from diagnostic data", True, True, "python", "disable_tailored_experiences"),
    "disable_app_launch_tracking": FixDefinition("disable_app_launch_tracking", "Disable app launch and document tracking", False, True, "python", "disable_app_launch_tracking"),
    "disable_lock_screen_camera": FixDefinition("disable_lock_screen_camera", "Disable lock-screen camera access", True, True, "python", "disable_lock_screen_camera"),
    "disable_lock_screen_notifications": FixDefinition("disable_lock_screen_notifications", "Disable lock-screen app notifications", True, True, "python", "disable_lock_screen_notifications"),
    "disable_windows_script_host": FixDefinition("disable_windows_script_host", "Disable Windows Script Host", True, True, "python", "disable_windows_script_host"),
    "enable_defender_scheduled_scan": FixDefinition("enable_defender_scheduled_scan", "Enable Defender scheduled daily scan", True, True, "powershell", "try { Set-MpPreference -ScanScheduleDay Everyday -ScanScheduleTime 02:00:00 -ErrorAction Stop } catch { Set-MpPreference -ScanScheduleDay 0 -ScanScheduleTime 02:00:00 -ErrorAction SilentlyContinue }; Write-Output 'Defender scheduled scan configured.'", 60),
    "enable_expanded_audit_policy": FixDefinition("enable_expanded_audit_policy", "Enable expanded Windows audit policy", True, True, "powershell", "foreach($s in @('Credential Validation','Account Lockout','User Account Management','Security Group Management','Audit Policy Change','Authentication Policy Change','Special Logon')){ auditpol /set /subcategory:$s /success:enable /failure:enable | Out-Null }; Write-Output 'Expanded audit policy enabled.'", 60),
    "disable_openssh_server": FixDefinition("disable_openssh_server", "Disable OpenSSH Server service", True, True, "powershell", "if(Get-Service -Name sshd -ErrorAction SilentlyContinue){ Stop-Service sshd -Force -ErrorAction SilentlyContinue; Set-Service sshd -StartupType Disabled -ErrorAction Stop; Write-Output 'OpenSSH Server disabled.' } else { Write-Output 'OpenSSH Server service not present.' }", 60),
    "disable_iis_services": FixDefinition("disable_iis_services", "Disable IIS web server services", True, True, "powershell", "foreach($n in @('W3SVC','WAS')){ if(Get-Service -Name $n -ErrorAction SilentlyContinue){ Stop-Service $n -Force -ErrorAction SilentlyContinue; Set-Service $n -StartupType Disabled -ErrorAction SilentlyContinue } }; Write-Output 'IIS web server services disabled where present.'", 60),
    "disable_function_discovery_services": FixDefinition("disable_function_discovery_services", "Disable Function Discovery publishing services", True, True, "powershell", "foreach($n in @('FDResPub','fdPHost')){ if(Get-Service -Name $n -ErrorAction SilentlyContinue){ Stop-Service $n -Force -ErrorAction SilentlyContinue; Set-Service $n -StartupType Disabled -ErrorAction SilentlyContinue } }; Write-Output 'Function Discovery services disabled where present.'", 60),
    "disable_teredo_tunneling": FixDefinition("disable_teredo_tunneling", "Disable Teredo, ISATAP, and 6to4 tunneling", True, True, "powershell", "netsh interface teredo set state disabled | Out-Null; netsh interface isatap set state disabled | Out-Null; netsh interface 6to4 set state disabled | Out-Null; Write-Output 'IPv6 transition tunneling disabled.'", 60, "Network reconnect or restart may be required."),
    "harden_tcpip_stack": FixDefinition("harden_tcpip_stack", "Harden TCP/IP source-routing and redirect behavior", True, True, "python", "harden_tcpip_stack", 60, "Restart may be required for TCP/IP stack changes."),
    "disable_cdrom_autorun": FixDefinition("disable_cdrom_autorun", "Disable CD/DVD AutoRun", True, True, "python", "disable_cdrom_autorun"),
    "disable_windows_error_reporting": FixDefinition("disable_windows_error_reporting", "Disable Windows Error Reporting upload prompts", True, True, "python", "disable_windows_error_reporting"),
    "disable_consumer_experiences": FixDefinition("disable_consumer_experiences", "Disable Windows consumer suggestions and silent app suggestions", True, True, "python", "disable_consumer_experiences"),
    "disable_winrm_basic_auth": FixDefinition("disable_winrm_basic_auth", "Disable WinRM Basic authentication", True, True, "python", "disable_winrm_basic_auth"),
    "disable_winrm_unencrypted": FixDefinition("disable_winrm_unencrypted", "Disable WinRM unencrypted traffic", True, True, "python", "disable_winrm_unencrypted"),
    "disable_winrm_remote_shell": FixDefinition("disable_winrm_remote_shell", "Disable WinRM remote shell access", True, True, "python", "disable_winrm_remote_shell"),
    "harden_rdp_nla": FixDefinition("harden_rdp_nla", "Require RDP Network Level Authentication", True, True, "python", "harden_rdp_nla"),
    "disable_rdp_redirection": FixDefinition("disable_rdp_redirection", "Disable RDP drive, clipboard, and device redirection", True, True, "python", "disable_rdp_redirection"),
    "disable_admin_shares": FixDefinition("disable_admin_shares", "Disable automatic administrative shares", True, True, "python", "disable_admin_shares", 60, "Restart may be required for LanmanServer policy changes."),
    "clear_null_sessions": FixDefinition("clear_null_sessions", "Clear null-session shares and pipes", True, True, "python", "clear_null_sessions"),
    "enable_attachment_manager_scan": FixDefinition("enable_attachment_manager_scan", "Require Attachment Manager antivirus scanning", True, True, "python", "enable_attachment_manager_scan"),
    "disable_recent_docs_history": FixDefinition("disable_recent_docs_history", "Disable recent document history", False, True, "python", "disable_recent_docs_history"),
    "disable_feedback_notifications": FixDefinition("disable_feedback_notifications", "Disable Windows feedback notifications", True, True, "python", "disable_feedback_notifications"),
    "disable_ceip": FixDefinition("disable_ceip", "Disable Customer Experience Improvement Program", True, True, "python", "disable_ceip"),
    "disable_app_telemetry": FixDefinition("disable_app_telemetry", "Disable application telemetry and inventory collection", True, True, "python", "disable_app_telemetry"),
    "disable_wifi_sense": FixDefinition("disable_wifi_sense", "Disable Wi-Fi Sense/OEM auto-connect behavior", True, True, "python", "disable_wifi_sense"),
    "disable_content_delivery": FixDefinition("disable_content_delivery", "Disable Windows content delivery suggestions", False, True, "python", "disable_content_delivery"),
    "disable_input_personalization": FixDefinition("disable_input_personalization", "Disable input personalization data collection", True, True, "python", "disable_input_personalization"),
    "enforce_uac_prompt_behavior": FixDefinition("enforce_uac_prompt_behavior", "Enforce safer UAC prompt behavior", True, True, "python", "enforce_uac_prompt_behavior", 60, "Restart may be required for UAC policy changes."),
    "restrict_rpc_clients": FixDefinition("restrict_rpc_clients", "Restrict unauthenticated RPC clients", True, True, "python", "restrict_rpc_clients"),
    "enable_safe_dll_search": FixDefinition("enable_safe_dll_search", "Enable safe DLL search order", True, True, "python", "enable_safe_dll_search"),
    "enable_sehop": FixDefinition("enable_sehop", "Enable SEH overwrite protection", True, True, "python", "enable_sehop", 60, "Restart may be required."),
    "disable_remote_desktop_firewall_group": FixDefinition("disable_remote_desktop_firewall_group", "Disable Remote Desktop inbound firewall rules", True, True, "powershell", "Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' } | Disable-NetFirewallRule -ErrorAction SilentlyContinue; Write-Output 'Remote Desktop inbound firewall rules disabled where present.'", 60),
    "disable_remote_assistance_firewall_group": FixDefinition("disable_remote_assistance_firewall_group", "Disable Remote Assistance inbound firewall rules", True, True, "powershell", "Get-NetFirewallRule -DisplayGroup 'Remote Assistance' -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' } | Disable-NetFirewallRule -ErrorAction SilentlyContinue; Write-Output 'Remote Assistance inbound firewall rules disabled where present.'", 60),
    "disable_media_sharing_service": FixDefinition("disable_media_sharing_service", "Disable Windows Media Player sharing service", True, True, "powershell", "if(Get-Service -Name WMPNetworkSvc -ErrorAction SilentlyContinue){ Stop-Service WMPNetworkSvc -Force -ErrorAction SilentlyContinue; Set-Service WMPNetworkSvc -StartupType Disabled -ErrorAction SilentlyContinue; Write-Output 'Media sharing service disabled.' } else { Write-Output 'Media sharing service not present.' }", 60),
    "disable_xbox_services": FixDefinition("disable_xbox_services", "Disable Xbox networking/game services", True, True, "powershell", "foreach($n in @('XboxNetApiSvc','XblAuthManager','XblGameSave','XboxGipSvc')){ if(Get-Service -Name $n -ErrorAction SilentlyContinue){ Stop-Service $n -Force -ErrorAction SilentlyContinue; Set-Service $n -StartupType Disabled -ErrorAction SilentlyContinue } }; Write-Output 'Xbox networking/game services disabled where present.'", 60),
    "disable_geolocation_service": FixDefinition("disable_geolocation_service", "Disable Geolocation service", True, True, "powershell", "if(Get-Service -Name lfsvc -ErrorAction SilentlyContinue){ Stop-Service lfsvc -Force -ErrorAction SilentlyContinue; Set-Service lfsvc -StartupType Disabled -ErrorAction SilentlyContinue; Write-Output 'Geolocation service disabled.' } else { Write-Output 'Geolocation service not present.' }", 60),
    "harden_windows_installer": FixDefinition("harden_windows_installer", "Harden Windows Installer policy", True, True, "python", "harden_windows_installer"),
}


def execute_fix(action: str) -> Dict[str, Any]:
    fix = FIXES.get(action)
    if not fix:
        AuditLogger.write("fix_rejected", {"action": action, "reason": "not_allowlisted"})
        return {"ok": False, "action": action, "message": "Rejected: action is not allowlisted."}
    if fix.requires_admin and not is_admin():
        AuditLogger.write("fix_rejected", {"action": action, "reason": "admin_required"})
        return {"ok": False, "action": action, "message": "Administrator rights are required. Restart the dashboard using the admin launcher or run the Python script as Administrator."}

    if fix.command_kind == "powershell":
        assert isinstance(fix.command, str)
        result = ps_fix(fix.command, fix.action, fix.timeout)
    elif fix.command_kind == "cmd":
        assert isinstance(fix.command, list)
        result = cmd_fix(fix.command, fix.action, fix.timeout)
    elif fix.command_kind == "python":
        assert isinstance(fix.command, str)
        result = python_fix(fix.command)
    else:
        result = CommandResult(False, "", "Invalid remediation command kind.", 1, fix.action)

    ok = result.ok
    message = "Fix completed." if ok else f"Fix failed: {compact_error(result.stderr or result.stdout or 'Unknown error')}"
    if ok and fix.restart_note:
        message += f" {fix.restart_note}"
    AuditLogger.write("fix_executed", {"action": action, "ok": ok, "returncode": result.returncode, "stderr": result.stderr[:500], "stdout": result.stdout[:500]})
    return {
        "ok": ok,
        "action": action,
        "title": fix.title,
        "message": message,
        "returncode": result.returncode,
        "stdout": result.stdout[:1200],
        "stderr": result.stderr[:1200],
        "restart_note": fix.restart_note,
    }


def execute_fix_all(actions: Iterable[str]) -> Dict[str, Any]:
    results = []
    for action in actions:
        fix = FIXES.get(action)
        if not fix or not fix.safe_for_fix_all:
            results.append({"ok": False, "action": action, "message": "Skipped: not approved for fix-all."})
            continue
        if fix.requires_admin and not is_admin():
            results.append({"ok": False, "action": action, "title": fix.title, "message": "Skipped: Administrator rights are required. Use Run_Dashboard_Admin.bat."})
            AuditLogger.write("fix_skipped", {"action": action, "reason": "admin_required_in_fix_all"})
            continue
        results.append(execute_fix(action))
    return {"ok": all(r.get("ok") for r in results) if results else True, "results": results}


class DashboardState:
    def __init__(self) -> None:
        self.token = secrets.token_urlsafe(32)
        self.last_scan: Optional[Dict[str, Any]] = None
        self.lock = threading.Lock()


STATE = DashboardState()


class SecureDashboardHandler(BaseHTTPRequestHandler):
    server_version = "CyberDashboardHTTP/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        AuditLogger.write("http_request", {"client": self.client_address[0], "message": fmt % args})

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        super().end_headers()

    def _reject(self, status: HTTPStatus, message: str) -> None:
        body = json.dumps({"ok": False, "error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _validate_host(self) -> bool:
        host = self.headers.get("Host", "")
        host_only = host.split(":", 1)[0].strip().lower()
        return host_only in {"127.0.0.1", "localhost"}

    def _validate_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            parsed = urllib.parse.urlparse(origin)
            return parsed.hostname in {"127.0.0.1", "localhost"}
        except Exception:
            return False

    def _validate_token(self) -> bool:
        token = self.headers.get("X-Dashboard-Token", "")
        return secrets.compare_digest(token, STATE.token)

    def _read_json(self) -> Optional[Dict[str, Any]]:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError:
            self._reject(HTTPStatus.BAD_REQUEST, "Invalid Content-Length.")
            return None
        if length > MAX_JSON_BODY_BYTES:
            self._reject(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "JSON body too large.")
            return None
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("JSON payload must be an object.")
            return payload
        except Exception:
            self._reject(HTTPStatus.BAD_REQUEST, "Invalid JSON payload.")
            return None

    def _send_json(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_file(self, path: Path, content_type: str) -> None:
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            self._reject(HTTPStatus.NOT_FOUND, "File not found.")
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        if not self._validate_host():
            self._reject(HTTPStatus.FORBIDDEN, "Invalid Host header.")
            return
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        if route in {"/", "/index.html"}:
            template = (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")
            safe_token = STATE.token.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
            html = template.replace("{{TOKEN}}", safe_token).replace("{{APP_VERSION}}", APP_VERSION)
            raw = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if route == "/assets/app.js":
            self._send_file(FRONTEND_DIR / "assets" / "app.js", "application/javascript; charset=utf-8")
            return
        if route == "/assets/styles.css":
            self._send_file(FRONTEND_DIR / "assets" / "styles.css", "text/css; charset=utf-8")
            return
        if route == "/api/health":
            self._send_json({"ok": True, "app": APP_NAME, "version": APP_VERSION, "admin": is_admin()})
            return
        self._reject(HTTPStatus.NOT_FOUND, "Unknown route.")

    def do_POST(self) -> None:  # noqa: N802 - stdlib method name
        if not self._validate_host() or not self._validate_origin():
            self._reject(HTTPStatus.FORBIDDEN, "Invalid request origin.")
            return
        if not self._validate_token():
            AuditLogger.write("auth_failed", {"path": self.path, "client": self.client_address[0]})
            self._reject(HTTPStatus.UNAUTHORIZED, "Invalid dashboard token.")
            return
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        payload = self._read_json()
        if payload is None:
            return
        try:
            if route == "/api/scan":
                with STATE.lock:
                    STATE.last_scan = run_scan()
                    self._send_json({"ok": True, "data": STATE.last_scan})
                return
            if route == "/api/fix":
                action = payload.get("action")
                if not isinstance(action, str) or not re.fullmatch(r"[a-z0-9_]{3,80}", action):
                    self._reject(HTTPStatus.BAD_REQUEST, "Invalid action.")
                    return
                result = execute_fix(action)
                self._send_json({"ok": bool(result.get("ok")), "data": result})
                return
            if route == "/api/fix-all":
                actions = payload.get("actions")
                if not isinstance(actions, list) or not all(isinstance(a, str) and re.fullmatch(r"[a-z0-9_]{3,80}", a) for a in actions):
                    self._reject(HTTPStatus.BAD_REQUEST, "Invalid actions list.")
                    return
                deduped = list(dict.fromkeys(actions))
                result = execute_fix_all(deduped)
                self._send_json({"ok": bool(result.get("ok")), "data": result})
                return
            self._reject(HTTPStatus.NOT_FOUND, "Unknown API route.")
        except Exception as exc:
            AuditLogger.write("api_error", {"path": route, "error": str(exc), "payload": redact_for_log(payload), "traceback": traceback.format_exc(limit=5)})
            self._reject(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal error. Details were written to the local audit log.")


def pick_port() -> int:
    for _ in range(50):
        port = random.randint(49152, 65520)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return int(s.getsockname()[1])


def main() -> int:
    os.chdir(str(BASE_DIR))
    port = pick_port()
    server = ThreadingHTTPServer((HOST, port), SecureDashboardHandler)
    url = f"http://{HOST}:{port}/"
    AuditLogger.write("server_started", {"url": url, "admin": is_admin(), "version": APP_VERSION})
    print(f"{APP_NAME} v{APP_VERSION}")
    print(f"Local dashboard: {url}")
    print("Security: localhost-only API, per-session token, allowlisted remediations, no remote dependencies.")
    print("Close this window or press Ctrl+C to stop the dashboard.")
    try:
        webbrowser.open(url, new=2)
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        AuditLogger.write("server_stopped", {"url": url})
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
