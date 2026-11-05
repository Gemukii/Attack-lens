"""Windows security posture, read without elevated rights.

Anything the current user cannot read stays None and is reported as unknown: a control
that could not be observed must never look like a control that passed.
"""

import getpass
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attacklens.models import Finding

COMMAND_TIMEOUT_SECONDS = 90
UPDATE_AGE_LIMIT_DAYS = 45
SIGNATURE_AGE_LIMIT_DAYS = 7
BITLOCKER_ON_VALUES = {1, 3, 5}

# One PowerShell run: starting it costs more than the checks themselves.
COLLECTOR = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = [ordered]@{}

try {
  $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
  $count = $searcher.GetTotalHistoryCount()
  if ($count -gt 0) {
    $done = $searcher.QueryHistory(0, [Math]::Min($count, 50)) |
      Where-Object { $_.ResultCode -eq 2 } | Sort-Object Date -Descending | Select-Object -First 1
    if ($done) { $out.last_update = $done.Date.ToUniversalTime().ToString('o') }
  }
} catch {}

$mp = Get-MpComputerStatus
if ($mp) {
  $out.defender = [ordered]@{
    running_mode = [string]$mp.AMRunningMode
    realtime = [bool]$mp.RealTimeProtectionEnabled
    signature_age_days = [int]$mp.AntivirusSignatureAge
    tamper_protected = [bool]$mp.IsTamperProtected
  }
}

try {
  $drive = (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\').Self
  $value = $drive.ExtendedProperty('System.Volume.BitLockerProtection')
  if ($null -ne $value) { $out.bitlocker = [int]$value }
} catch {}

$system = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if ($system) {
  $out.uac = [ordered]@{
    enabled = [int]$system.EnableLUA
    admin_prompt = [int]$system.ConsentPromptBehaviorAdmin
  }
}

$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
if ($rdp) {
  $out.rdp = [ordered]@{ enabled = ([int]$rdp.fDenyTSConnections -eq 0); nla = ([int]$nla.UserAuthentication -eq 1) }
}

$admins = Get-LocalGroupMember -SID 'S-1-5-32-544'
if ($admins) { $out.administrators = @($admins | ForEach-Object { [string]$_.Name }) }
$guest = Get-LocalUser | Where-Object { $_.SID -like '*-501' }
if ($guest) { $out.guest_enabled = [bool]$guest.Enabled }

$smb = Get-SmbServerConfiguration
if ($smb) {
  $out.smb = [ordered]@{ smb1 = [bool]$smb.EnableSMB1Protocol; signing_required = [bool]$smb.RequireSecuritySignature }
  $out.smb.server_running = ((Get-Service LanmanServer).Status -eq 'Running')
}

$autoruns = @()
foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
  $item = Get-Item $key
  if ($item) { foreach ($name in $item.GetValueNames()) {
    $autoruns += [ordered]@{ kind = 'run key'; name = $name; command = [string]$item.GetValue($name) }
  } }
}
foreach ($folder in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
  Get-ChildItem $folder -File | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
    $autoruns += [ordered]@{ kind = 'startup folder'; name = $_.Name; command = $_.FullName }
  }
}
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object {
  $action = $_.Actions | Select-Object -First 1
  $autoruns += [ordered]@{ kind = 'scheduled task'; name = $_.TaskName; command = [string]$action.Execute }
}
Get-CimInstance Win32_Service -Filter "StartMode='Auto'" |
  Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\windows\\' } | ForEach-Object {
    $autoruns += [ordered]@{ kind = 'service'; name = $_.Name; command = [string]$_.PathName }
  }
$out.autoruns = $autoruns

$out | ConvertTo-Json -Depth 5 -Compress
"""


def _powershell_path() -> str:
    """Return the system PowerShell, never one found earlier in the PATH."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return str(Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe")


def executable_of(command: str) -> str:
    """Return the program of a command line, without arguments that may hold secrets."""
    command = command.strip()
    quoted = re.match(r'"([^"]+)"', command)
    if quoted:
        return quoted.group(1)
    match = re.match(r"(.+?\.(?:exe|cmd|bat|ps1|vbs|lnk|com))\b", command, re.IGNORECASE)
    return match.group(1) if match else command.split(" ", 1)[0]


def collect_windows_posture() -> dict[str, Any]:
    """Read the posture of this Windows machine."""
    try:
        completed = subprocess.run(
            [_powershell_path(), "-NoProfile", "-NonInteractive", "-Command", COLLECTOR],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
        data = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return {"status": "unknown", "detail": str(error)[:200], "autoruns": []}

    for entry in data.get("autoruns") or []:
        entry["command"] = executable_of(entry.get("command") or "")
    data["user_is_admin"] = is_listed_admin(data.get("administrators"), getpass.getuser())
    return {"status": "complete", **data, "autoruns": data.get("autoruns") or []}


def is_listed_admin(administrators: list[str] | str | None, user: str) -> bool | None:
    """Return whether a user is in the local administrators, or None if unreadable."""
    if not administrators:
        return None
    names = [administrators] if isinstance(administrators, str) else administrators
    return any(name.rsplit("\\", 1)[-1].lower() == user.lower() for name in names)


def parse_winget_upgrades(output: str) -> list[dict[str, str]]:
    """Parse `winget upgrade`. The headers are localized, so only the row shape is used."""
    upgrades = []
    for line in output.splitlines():
        match = re.match(
            r"^(?P<name>\S.*?)\s+(?P<id>[\w.+-]+\.[\w.+-]+|[A-Z0-9]{12})\s+"
            r"(?P<installed>\S+)\s+(?P<available>\S+)\s+(?P<source>winget|msstore)\s*$",
            line,
        )
        if match:
            upgrades.append(match.groupdict())
    return upgrades


def collect_outdated_software() -> dict[str, Any]:
    """List the software with a newer version available."""
    try:
        completed = subprocess.run(
            [
                "winget",
                "upgrade",
                "--accept-source-agreements",
                "--disable-interactivity",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {"status": "unknown", "items": []}
    return {"status": "complete", "items": parse_winget_upgrades(completed.stdout)}


def _days_since(moment: str, now: datetime) -> int | None:
    """Return the age of an ISO date in days."""
    try:
        return (now - datetime.fromisoformat(moment)).days
    except (TypeError, ValueError):
        return None


def _check(
    target: str, severity: str, title: str, description: str, remediation: str, evidence: str = ""
) -> Finding:
    """Build a posture finding."""
    return Finding(
        category="posture",
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        target=target,
    )


def _unknown(target: str, control: str) -> Finding:
    """Report a control that could not be read."""
    return _check(
        target,
        "info",
        f"{control} could not be checked",
        "This control is not readable by the current user.",
        "Verify it manually.",
    )


def _update_findings(target: str, data: dict[str, Any], now: datetime) -> list[Finding]:
    """Check how recently Windows Update installed something."""
    age = _days_since(data.get("last_update") or "", now)
    if age is None:
        return [_unknown(target, "Windows Update history")]
    if age <= UPDATE_AGE_LIMIT_DAYS:
        return []
    return [
        _check(
            target,
            "high",
            "Windows updates are late",
            f"The last update was installed {age} days ago.",
            "Open Windows Update and install the pending updates.",
            f"{age} days",
        )
    ]


def _defender_findings(target: str, data: dict[str, Any]) -> list[Finding]:
    """Check the antivirus. Another product may legitimately replace Defender."""
    defender = data.get("defender")
    if not defender:
        return [_unknown(target, "Microsoft Defender")]
    findings = []
    if defender.get("running_mode") == "Normal" or defender.get("realtime"):
        if not defender.get("realtime"):
            findings.append(
                _check(
                    target,
                    "high",
                    "Real-time antivirus protection is off",
                    "Microsoft Defender is not scanning files as they are used.",
                    "Enable real-time protection in Windows Security.",
                )
            )
        age = defender.get("signature_age_days", 0)
        if age > SIGNATURE_AGE_LIMIT_DAYS:
            findings.append(
                _check(
                    target,
                    "medium",
                    "Antivirus signatures are old",
                    f"Defender signatures are {age} days old.",
                    "Update the signatures from Windows Security.",
                    f"{age} days",
                )
            )
        if not defender.get("tamper_protected"):
            findings.append(
                _check(
                    target,
                    "medium",
                    "Tamper protection is off",
                    "Malware can turn the antivirus off without resistance.",
                    "Enable Tamper Protection in Windows Security.",
                )
            )
    return findings


def _account_findings(target: str, data: dict[str, Any]) -> list[Finding]:
    """Check how much a compromised session would be able to do."""
    findings = []
    uac = data.get("uac")
    if uac is None:
        findings.append(_unknown(target, "User Account Control"))
    elif not uac.get("enabled") or uac.get("admin_prompt") == 0:
        findings.append(
            _check(
                target,
                "high",
                "User Account Control does not prompt",
                "Programs can gain administrator rights without any confirmation.",
                "Set User Account Control to always notify.",
            )
        )
    if data.get("user_is_admin") is None:
        findings.append(_unknown(target, "Membership of the administrators group"))
    elif data["user_is_admin"]:
        findings.append(
            _check(
                target,
                "low",
                "The daily account is an administrator",
                "Malware running in this session is one prompt away from full control.",
                "Use a standard account daily and keep a separate administrator account.",
            )
        )
    if data.get("guest_enabled"):
        findings.append(
            _check(
                target,
                "medium",
                "The Guest account is enabled",
                "This built-in account allows access without a personal identity.",
                "Disable the Guest account.",
            )
        )
    return findings


def _access_findings(target: str, data: dict[str, Any]) -> list[Finding]:
    """Check remote access and disk encryption."""
    findings = []
    rdp = data.get("rdp") or {}
    if rdp.get("enabled"):
        findings.append(
            _check(
                target,
                "medium" if rdp.get("nla") else "high",
                "Remote Desktop is enabled",
                "Remote Desktop is a frequent target of password attacks."
                + ("" if rdp.get("nla") else " Network Level Authentication is off."),
                "Disable it if unused, or restrict it to a VPN.",
            )
        )

    smb = data.get("smb")
    if smb and smb.get("smb1"):
        findings.append(
            _check(
                target,
                "high",
                "SMB1 is enabled",
                "This obsolete protocol is the one used by WannaCry.",
                "Disable the SMB1 Windows feature.",
            )
        )
    if smb and smb.get("server_running") and not smb.get("signing_required"):
        findings.append(
            _check(
                target,
                "low",
                "SMB signing is not required",
                "Without signing, SMB traffic can be relayed by an attacker on the network.",
                "Run: Set-SmbServerConfiguration -RequireSecuritySignature $true",
            )
        )

    bitlocker = data.get("bitlocker")
    if bitlocker is None:
        findings.append(_unknown(target, "Disk encryption"))
    elif bitlocker not in BITLOCKER_ON_VALUES:
        findings.append(
            _check(
                target,
                "medium",
                "The system disk is not encrypted",
                "Anyone with the laptop in hand can read its disk.",
                "Enable BitLocker or Device Encryption.",
            )
        )
    return findings


def persistence_findings(target: str, data: dict[str, Any]) -> list[Finding]:
    """List what starts by itself.

    These are informational, as most entries are legitimate. Their value is in the change:
    the pipeline alerts on any new entry, whatever its severity.
    """
    return [
        Finding(
            category="persistence",
            severity="info",
            title=f"Starts automatically ({entry['kind']}): {entry['name']}",
            description=f"This {entry['kind']} runs without user action.",
            evidence=entry.get("command", ""),
            remediation="If you do not recognize it, investigate before removing it.",
            risk_reason="Malware uses these same mechanisms to survive a reboot.",
            target=target,
        )
        for entry in data.get("autoruns", [])
        if entry.get("name")
    ]


def software_findings(target: str, outdated: dict[str, Any]) -> list[Finding]:
    """Turn available upgrades into findings."""
    return [
        Finding(
            category="software",
            severity="low",
            title=f"Update available: {item['name']}",
            description=f"Version {item['available']} is available.",
            evidence=f"{item['installed']} -> {item['available']}",
            remediation=f"Run: winget upgrade --id {item['id']} --exact",
            risk_reason="Outdated software is a common way in. Not every update fixes a flaw.",
            target=target,
            service=item["id"],
            version=item["installed"],
        )
        for item in outdated.get("items", [])
    ]


def posture_findings(
    target: str, data: dict[str, Any], now: datetime | None = None
) -> list[Finding]:
    """Evaluate the collected posture."""
    if data.get("status") != "complete":
        return [_unknown(target, "Windows posture")]
    now = now or datetime.now(UTC)
    return [
        *_update_findings(target, data, now),
        *_defender_findings(target, data),
        *_account_findings(target, data),
        *_access_findings(target, data),
    ]
