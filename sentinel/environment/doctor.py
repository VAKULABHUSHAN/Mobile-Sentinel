"""Environment and system tool detection engine for Mobile Sentinel."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from colorama import Fore, Style, init

from sentinel.core.enums import ToolStatus
from sentinel.core.models import EnvironmentReport, ToolCheckResult

init(autoreset=True)


class EnvironmentDoctor:
    """Probes the host environment for required and optional tooling."""

    def __init__(self, timeout_seconds: int = 5):
        self.timeout_seconds = timeout_seconds

    def _run_command(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Safely executes an external command with timeout."""
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            return res.returncode, res.stdout.strip(), res.stderr.strip()
        except FileNotFoundError:
            return -1, "", "Command not found"
        except subprocess.TimeoutExpired:
            return -2, "", "Command timed out"
        except Exception as e:
            return -3, "", str(e)

    def check_python(self) -> ToolCheckResult:
        """Inspects current Python runtime environment."""
        ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        path = sys.executable
        if sys.version_info.major >= 3 and sys.version_info.minor >= 11:
            return ToolCheckResult(
                name="Python",
                status=ToolStatus.AVAILABLE,
                found=True,
                version=ver,
                path=path,
                details=f"Compatible Python runtime ({ver}) on {sys.platform}",
                required=True,
            )
        return ToolCheckResult(
            name="Python",
            status=ToolStatus.DEGRADED,
            found=True,
            version=ver,
            path=path,
            details=f"Python version {ver} is older than recommended (>=3.11)",
            required=True,
            remediation="Upgrade Python to version 3.11 or newer (Python 3.14 recommended).",
        )

    def check_adb(self) -> ToolCheckResult:
        """Inspects ADB (Android Debug Bridge) availability."""
        adb_path = shutil.which("adb")
        # Check standard Android SDK location if not directly on PATH
        if not adb_path:
            candidate = self._find_sdk_tool("platform-tools", "adb")
            if candidate and candidate.exists():
                adb_path = str(candidate)

        if not adb_path:
            return ToolCheckResult(
                name="ADB",
                status=ToolStatus.MISSING,
                found=False,
                required=False,
                details="ADB binary not found on PATH or Android SDK platform-tools",
                remediation="Install Android SDK Platform-Tools or add directory to system PATH.",
            )

        code, out, _ = self._run_command([adb_path, "version"])
        ver = None
        if code == 0 and "Android Debug Bridge version" in out:
            for line in out.splitlines():
                if "Android Debug Bridge version" in line:
                    ver = line.split("version")[-1].strip()
                    break

        return ToolCheckResult(
            name="ADB",
            status=ToolStatus.AVAILABLE,
            found=True,
            version=ver or "Detected",
            path=adb_path,
            details=f"Android Debug Bridge active at {adb_path}",
            required=False,
        )

    def check_android_sdk(self) -> ToolCheckResult:
        """Checks Android SDK installation paths and components."""
        sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if not sdk_root:
            default_win = Path.home() / "AppData" / "Local" / "Android" / "Sdk"
            if default_win.exists():
                sdk_root = str(default_win)

        if not sdk_root or not Path(sdk_root).exists():
            return ToolCheckResult(
                name="Android SDK",
                status=ToolStatus.MISSING,
                found=False,
                required=False,
                details="ANDROID_HOME / ANDROID_SDK_ROOT not set and default location missing",
                remediation="Install Android Studio or Android Command Line Tools and set ANDROID_HOME.",
            )

        sdk_path = Path(sdk_root)
        has_platform_tools = (sdk_path / "platform-tools").exists()
        has_build_tools = (sdk_path / "build-tools").exists()

        status = ToolStatus.AVAILABLE if (has_platform_tools or has_build_tools) else ToolStatus.DEGRADED
        return ToolCheckResult(
            name="Android SDK",
            status=status,
            found=True,
            path=str(sdk_path),
            details=f"Android SDK located at {sdk_path} (platform-tools: {has_platform_tools}, build-tools: {has_build_tools})",
            required=False,
        )

    def check_java(self) -> ToolCheckResult:
        """Checks Java runtime (JDK or Android Studio JBR)."""
        java_path = shutil.which("java")
        if not java_path:
            java_home = os.environ.get("JAVA_HOME")
            if java_home:
                candidate = Path(java_home) / "bin" / ("java.exe" if sys.platform == "win32" else "java")
                if candidate.exists():
                    java_path = str(candidate)

        # Fallback to Android Studio bundled JBR
        if not java_path and sys.platform == "win32":
            studio_jbr = Path("C:/Program Files/Android/Android Studio/jbr/bin/java.exe")
            if studio_jbr.exists():
                java_path = str(studio_jbr)

        if not java_path:
            return ToolCheckResult(
                name="Java",
                status=ToolStatus.MISSING,
                found=False,
                required=False,
                details="Java runtime not found on PATH, JAVA_HOME, or Android Studio JBR",
                remediation="Install OpenJDK 17+ or configure Android Studio JBR.",
            )

        code, out, err = self._run_command([java_path, "-version"])
        ver_text = err if err else out
        ver = "Detected"
        if ver_text:
            first_line = ver_text.splitlines()[0]
            ver = first_line.replace('"', "")

        return ToolCheckResult(
            name="Java",
            status=ToolStatus.AVAILABLE,
            found=True,
            version=ver,
            path=java_path,
            details=f"Java runtime active at {java_path}",
            required=False,
        )

    def check_flutter(self) -> ToolCheckResult:
        """Checks Flutter SDK and CLI tool."""
        flutter_path = shutil.which("flutter")
        if not flutter_path and sys.platform == "win32":
            # Check common Flutter locations on Windows
            candidates = [
                Path("C:/flutter/flutter/bin/flutter.bat"),
                Path("C:/src/flutter/bin/flutter.bat"),
                Path.home() / "flutter" / "bin" / "flutter.bat",
            ]
            for c in candidates:
                if c.exists():
                    flutter_path = str(c)
                    break

        if not flutter_path:
            return ToolCheckResult(
                name="Flutter",
                status=ToolStatus.MISSING,
                found=False,
                required=False,
                details="Flutter executable not found on system PATH",
                remediation="Install Flutter SDK (https://flutter.dev) and add bin directory to PATH.",
            )

        code, out, _ = self._run_command([flutter_path, "--version"])
        ver = "Detected"
        if code == 0 and out:
            first_line = out.splitlines()[0]
            ver = first_line

        return ToolCheckResult(
            name="Flutter",
            status=ToolStatus.AVAILABLE,
            found=True,
            version=ver,
            path=flutter_path,
            details=f"Flutter SDK detected at {flutter_path}",
            required=False,
        )

    def check_connected_device(self, adb_result: Optional[ToolCheckResult] = None) -> ToolCheckResult:
        """Inspects whether an Android device or emulator is connected and authorized."""
        adb = adb_result or self.check_adb()
        if not adb.found:
            return ToolCheckResult(
                name="Connected Device",
                status=ToolStatus.SKIPPED,
                found=False,
                required=False,
                details="ADB not available; device check skipped.",
                remediation="Configure ADB to enable connected device inspection.",
            )

        code, out, _ = self._run_command([adb.path or "adb", "devices"])
        if code != 0:
            return ToolCheckResult(
                name="Connected Device",
                status=ToolStatus.DEGRADED,
                found=False,
                required=False,
                details="Failed to query ADB for connected devices.",
                remediation="Ensure ADB server is running (`adb start-server`).",
            )

        lines = out.splitlines()
        devices: List[str] = []
        unauthorized: List[str] = []
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 2:
                serial, state = parts[0], parts[1]
                if state == "device":
                    devices.append(serial)
                elif state in ("unauthorized", "offline"):
                    unauthorized.append(f"{serial} ({state})")

        if devices:
            return ToolCheckResult(
                name="Connected Device",
                status=ToolStatus.AVAILABLE,
                found=True,
                version=f"{len(devices)} device(s)",
                details=f"Active device(s): {', '.join(devices)}",
                required=False,
            )
        elif unauthorized:
            return ToolCheckResult(
                name="Connected Device",
                status=ToolStatus.DEGRADED,
                found=True,
                version="Unauthorized",
                details=f"Device found but not authorized: {', '.join(unauthorized)}",
                required=False,
                remediation="Accept the USB debugging authorization prompt on the device screen.",
            )

        return ToolCheckResult(
            name="Connected Device",
            status=ToolStatus.DEGRADED,
            found=False,
            required=False,
            details="No connected Android devices or running emulators detected.",
            remediation="Start an emulator via Android Studio or connect a physical device with USB debugging enabled.",
        )

    def check_apk_processing(self) -> ToolCheckResult:
        """Checks availability of APK extraction dependencies and tooling."""
        import zipfile
        import xml.etree.ElementTree

        aapt_path = shutil.which("aapt") or shutil.which("aapt2")
        if not aapt_path:
            candidate = self._find_sdk_tool("build-tools", "aapt")
            if candidate and candidate.exists():
                aapt_path = str(candidate)

        if aapt_path:
            return ToolCheckResult(
                name="APK Processing",
                status=ToolStatus.AVAILABLE,
                found=True,
                version="Full (zipfile+aapt)",
                path=str(aapt_path),
                details=f"Full APK extraction tooling active with aapt binary at {aapt_path}",
                required=True,
            )

        return ToolCheckResult(
            name="APK Processing",
            status=ToolStatus.AVAILABLE,
            found=True,
            version="Standard (zipfile)",
            details="Standard pure-Python APK extraction active (zipfile); aapt binary optional.",
            required=True,
            remediation="Install Android SDK Build-Tools for enhanced aapt badging extraction.",
        )

    def check_ai_config(self) -> ToolCheckResult:
        """Inspects AI intelligence layer configuration and settings."""
        try:
            from sentinel.ai.config import AIConfig
            cfg = AIConfig.from_env()
            if cfg.enabled:
                return ToolCheckResult(
                    name="AI Configuration",
                    status=ToolStatus.AVAILABLE,
                    found=True,
                    version=f"{cfg.provider}:{cfg.model}",
                    details=f"AI Intelligence Layer enabled (Provider: '{cfg.provider}', Model: '{cfg.model}')",
                    required=False,
                )
            return ToolCheckResult(
                name="AI Configuration",
                status=ToolStatus.AVAILABLE,
                found=True,
                version="Disabled",
                details="AI Layer disabled (SENTINEL_AI_ENABLED=false). Local deterministic analysis active.",
                required=False,
                remediation="Set SENTINEL_AI_ENABLED=true in .env to activate AI screen understanding and reports.",
            )
        except Exception as e:
            return ToolCheckResult(
                name="AI Configuration",
                status=ToolStatus.DEGRADED,
                found=False,
                details=f"Failed to load AI configuration: {e}",
                required=False,
                remediation="Verify syntax in .env file.",
            )

    def check_ai_provider(self, config: Optional[Any] = None) -> ToolCheckResult:
        """Inspects availability and credentials for the selected AI provider."""
        try:
            from sentinel.ai.config import AIConfig
            cfg = config or AIConfig.from_env()

            if not cfg.enabled:
                return ToolCheckResult(
                    name="AI Provider",
                    status=ToolStatus.SKIPPED,
                    found=True,
                    version="Skipped",
                    details="AI Layer is disabled; provider availability check skipped.",
                    required=False,
                )

            prov = (cfg.provider or "gemini").lower()
            if prov == "mock":
                return ToolCheckResult(
                    name="AI Provider",
                    status=ToolStatus.AVAILABLE,
                    found=True,
                    version="Mock Provider",
                    details="MockLLMProvider active for offline test execution.",
                    required=False,
                )

            if prov == "gemini":
                key = cfg.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("AI_API_KEY")
                if key and key.strip():
                    return ToolCheckResult(
                        name="AI Provider (Gemini)",
                        status=ToolStatus.AVAILABLE,
                        found=True,
                        version=cfg.model,
                        details="Gemini API credentials configured.",
                        required=False,
                    )
                return ToolCheckResult(
                    name="AI Provider (Gemini)",
                    status=ToolStatus.DEGRADED,
                    found=False,
                    version="Missing Key",
                    details="Gemini provider selected but GEMINI_API_KEY is not set.",
                    required=False,
                    remediation="Add GEMINI_API_KEY=your_key to .env or environment, or run with --no-ai.",
                )

            if prov == "openai":
                key = cfg.api_key or os.environ.get("OPENAI_API_KEY")
                if key and key.strip():
                    return ToolCheckResult(
                        name="AI Provider (OpenAI)",
                        status=ToolStatus.AVAILABLE,
                        found=True,
                        version=cfg.model,
                        details="OpenAI API credentials configured.",
                        required=False,
                    )
                return ToolCheckResult(
                    name="AI Provider (OpenAI)",
                    status=ToolStatus.DEGRADED,
                    found=False,
                    version="Missing Key",
                    details="OpenAI provider selected but OPENAI_API_KEY is not set.",
                    required=False,
                    remediation="Add OPENAI_API_KEY=your_key to .env or environment.",
                )

            if prov == "ollama":
                import urllib.request
                base_url = cfg.base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
                reachable = False
                try:
                    req = urllib.request.Request(f"{base_url.rstrip('/')}/api/tags", headers={"User-Agent": "SentinelDoctor"})
                    with urllib.request.urlopen(req, timeout=2) as resp:
                        if resp.status == 200:
                            reachable = True
                except Exception:
                    reachable = False

                if reachable:
                    return ToolCheckResult(
                        name="AI Provider (Ollama)",
                        status=ToolStatus.AVAILABLE,
                        found=True,
                        version=cfg.model,
                        details=f"Ollama local daemon reachable at {base_url}.",
                        required=False,
                    )
                return ToolCheckResult(
                    name="AI Provider (Ollama)",
                    status=ToolStatus.DEGRADED,
                    found=False,
                    version="Unreachable",
                    details=f"Ollama daemon unreachable at {base_url}.",
                    required=False,
                    remediation=f"Start Ollama with `ollama serve` and ensure model '{cfg.model}' is pulled.",
                )

            return ToolCheckResult(
                name="AI Provider",
                status=ToolStatus.DEGRADED,
                found=False,
                details=f"Unrecognized AI provider '{cfg.provider}'.",
                required=False,
                remediation="Set provider to 'gemini', 'openai', 'ollama', or 'mock'.",
            )
        except Exception as e:
            return ToolCheckResult(
                name="AI Provider",
                status=ToolStatus.DEGRADED,
                found=False,
                details=f"Error checking AI provider: {e}",
                required=False,
            )

    def check_report_directory(self, target_dir: str = "reports") -> ToolCheckResult:
        """Inspects read and write permissions for the reports output directory."""
        p = Path(target_dir).resolve()
        try:
            p.mkdir(parents=True, exist_ok=True)
            test_file = p / ".probe_write_perm"
            test_file.write_text("probe", encoding="utf-8")
            test_file.unlink()
            return ToolCheckResult(
                name="Report Directory",
                status=ToolStatus.AVAILABLE,
                found=True,
                path=str(p),
                details=f"Output directory is writable: {p}",
                required=True,
            )
        except Exception as e:
            return ToolCheckResult(
                name="Report Directory",
                status=ToolStatus.DEGRADED,
                found=False,
                path=str(p),
                details=f"Cannot write to output directory {p}: {e}",
                required=True,
                remediation=f"Check write permissions on {p} or specify another directory with --output.",
            )

    def _find_sdk_tool(self, subfolder: str, tool_name: str) -> Optional[Path]:
        """Locates a tool inside Android SDK directory."""
        sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if not sdk_root and sys.platform == "win32":
            default_win = Path.home() / "AppData" / "Local" / "Android" / "Sdk"
            if default_win.exists():
                sdk_root = str(default_win)
        if not sdk_root:
            return None

        ext = ".exe" if sys.platform == "win32" else ""
        candidate = Path(sdk_root) / subfolder / f"{tool_name}{ext}"
        if candidate.exists():
            return candidate

        # Also search for tools inside build-tools versioned subfolders (e.g. build-tools/34.0.0/aapt.exe)
        sub_dir = Path(sdk_root) / subfolder
        if sub_dir.exists() and sub_dir.is_dir():
            for child in sorted(sub_dir.iterdir(), reverse=True):
                if child.is_dir():
                    tool_cand = child / f"{tool_name}{ext}"
                    if tool_cand.exists():
                        return tool_cand

        return None

    def diagnose(self) -> EnvironmentReport:
        """Executes all system diagnostics and returns comprehensive EnvironmentReport."""
        adb_res = self.check_adb()
        results: Dict[str, ToolCheckResult] = {
            "python": self.check_python(),
            "adb": adb_res,
            "connected_device": self.check_connected_device(adb_res),
            "android_sdk": self.check_android_sdk(),
            "java": self.check_java(),
            "flutter": self.check_flutter(),
            "apk_processing": self.check_apk_processing(),
            "ai_config": self.check_ai_config(),
            "ai_provider": self.check_ai_provider(),
            "report_directory": self.check_report_directory(),
        }

        # Static analysis readiness: requires Python; Java, SDK, and AI are optional
        ready_for_scan = results["python"].found and results["python"].status != ToolStatus.MISSING

        # Runtime readiness: requires ADB
        ready_for_runtime = results["adb"].found and results["adb"].status == ToolStatus.AVAILABLE

        summary = (
            "Environment is fully ready for static and runtime analysis."
            if (ready_for_scan and ready_for_runtime)
            else "Environment is ready for static analysis. Runtime analysis requires ADB configuration."
            if ready_for_scan
            else "Environment is missing essential components for analysis."
        )

        return EnvironmentReport(
            ready_for_scan=ready_for_scan,
            ready_for_runtime=ready_for_runtime,
            tools=results,
            summary=summary,
        )

    @staticmethod
    def render_console_report(report: EnvironmentReport) -> str:
        """Formats the EnvironmentReport into a terminal display."""
        lines = [
            f"{Style.BRIGHT}================================================================{Style.RESET_ALL}",
            f"{Style.BRIGHT}                MOBILE SENTINEL - ENVIRONMENT DOCTOR            {Style.RESET_ALL}",
            f"{Style.BRIGHT}================================================================{Style.RESET_ALL}",
            "",
            f"  {Style.BRIGHT}{'TOOL / SUBSYSTEM':<22} {'STATUS':<14} {'DETAILS'}{Style.RESET_ALL}",
            f"  {'-'*20}   {'-'*12}   {'-'*26}",
        ]

        for _, tool in report.tools.items():
            if tool.status == ToolStatus.AVAILABLE:
                status_str = f"{Fore.GREEN}[PASS] OK     {Style.RESET_ALL}"
            elif tool.status == ToolStatus.DEGRADED:
                status_str = f"{Fore.YELLOW}[WARN] WARNING{Style.RESET_ALL}"
            elif tool.status == ToolStatus.SKIPPED:
                status_str = f"{Fore.CYAN}[SKIP] SKIPPED{Style.RESET_ALL}"
            else:
                status_str = f"{Fore.RED}[FAIL] MISSING{Style.RESET_ALL}"

            info = tool.version or tool.details
            if len(info) > 42:
                info = info[:39] + "..."
            lines.append(f"  {tool.name:<22} {status_str:<23} {info}")

        lines.append("")
        lines.append(f"  Static Scan Readiness:  {Fore.GREEN if report.ready_for_scan else Fore.RED}{'READY' if report.ready_for_scan else 'NOT READY'}{Style.RESET_ALL}")
        lines.append(f"  Runtime ADB Readiness:  {Fore.GREEN if report.ready_for_runtime else Fore.YELLOW}{'READY' if report.ready_for_runtime else 'DEGRADED / NOT READY'}{Style.RESET_ALL}")
        lines.append("")
        lines.append(f"  Summary: {report.summary}")

        missing_remediations = [t for t in report.tools.values() if t.remediation]
        if missing_remediations:
            lines.append("")
            lines.append(f"{Style.BRIGHT}Actionable Recommendations:{Style.RESET_ALL}")
            for t in missing_remediations:
                lines.append(f"  - [{t.name}]: {t.remediation}")

        lines.append(f"{Style.BRIGHT}================================================================{Style.RESET_ALL}")
        return "\n".join(lines)
