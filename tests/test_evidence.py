import json
from dva.evidence import generalize, build_query, summarize
from dva.hunting import run_named, GRAPH_BASE
from dva.http import Client
from dva.run import Run
from tests.fakes import FakeSession, FakeResponse, FakeTokens


def test_generalize_windows_paths():
    assert generalize(r"C:\Users\alice\AppData\Local\Google\Chrome\Application\chrome.exe") == r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"
    assert generalize(r"c:\users\bob\AppData\Roaming\Zoom\bin\Zoom.exe") == r"%APPDATA%\Zoom\bin\Zoom.exe"
    assert generalize(r"C:\Users\carol\Downloads\tool\tool.exe") == r"%USERPROFILE%\Downloads\tool\tool.exe"
    assert generalize(r"C:\Program Files (x86)\Java\jre1.8.0_431\bin\java.exe") == r"%ProgramFiles(x86)%\Java\<version>\bin\java.exe"
    assert generalize(r"D:\Apps\7-Zip\7z.exe") == r"<drive>:\Apps\7-Zip\7z.exe"
    assert generalize(r"C:\Windows\System32\drivers\x.sys") == r"%WINDIR%\System32\drivers\x.sys"
    assert generalize(r"C:\ProgramData\Vendor\1.2.3.4\svc.exe") == r"%ProgramData%\Vendor\<version>\svc.exe"


def test_generalize_posix_and_registry():
    assert generalize("/home/alice/.local/share/app/bin/app") == "~/.local/share/app/bin/app"
    assert generalize("/Users/bob/Applications/Zoom.app/Contents/MacOS/zoom") == "~/Applications/Zoom.app/Contents/MacOS/zoom"
    assert generalize("/usr/lib/jvm/java-11-openjdk-amd64/bin/java") == "/usr/lib/jvm/java-11-openjdk-amd64/bin/java"
    assert generalize(r"HKEY_USERS\S-1-5-21-2944539346-1310925172-2349113062-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe") == r"HKEY_USERS\<sid>\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe"
    assert generalize(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{C4EBFDFD-0C55-3E5F-A919-E3C54949024A}") == r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{<guid>}"


def test_build_query_scopes_products_and_caps():
    q = build_query([("google", "chrome"), ("adobe", "acrobat_reader_dc")], top=3000)
    assert 'SoftwareVendor in~ ("adobe", "google")' in q and 'SoftwareName in~ ("acrobat_reader_dc", "chrome")' in q
    assert "DeviceTvmSoftwareEvidenceBeta" in q and q.endswith("| take 3000")
    assert "mv-expand" in q and "dcount(DeviceId)" in q


def test_summarize_groups_generalized_paths():
    rows = [
        {"SoftwareVendor": "google", "SoftwareName": "chrome", "Kind": "disk", "Path": r"C:\Users\a\AppData\Local\Google\Chrome\Application\chrome.exe", "Devices": 3},
        {"SoftwareVendor": "google", "SoftwareName": "chrome", "Kind": "disk", "Path": r"C:\Users\b\AppData\Local\Google\Chrome\Application\chrome.exe", "Devices": 2},
        {"SoftwareVendor": "google", "SoftwareName": "chrome", "Kind": "disk", "Path": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "Devices": 40},
        {"SoftwareVendor": "google", "SoftwareName": "chrome", "Kind": "registry", "Path": r"HKEY_LOCAL_MACHINE\SOFTWARE\Google\Chrome", "Devices": 40},
        {"SoftwareVendor": "x", "SoftwareName": "y", "Kind": "disk", "Path": "", "Devices": 1},
    ]
    out = summarize(rows)
    assert list(out) == ["google/chrome"]
    assert out["google/chrome"] == [
        {"path": r"%ProgramFiles%\Google\Chrome\Application\chrome.exe", "kind": "disk", "devices": 40},
        {"path": r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe", "kind": "disk", "devices": 5},
        {"path": r"HKEY_LOCAL_MACHINE\SOFTWARE\Google\Chrome", "kind": "registry", "devices": 40},
    ]


def test_run_named_evidence_builds_dynamic_query(tmp_path):
    from tests.test_rollup import seed
    run = seed(tmp_path)
    s = FakeSession({f"POST {GRAPH_BASE}/security/runHuntingQuery": [FakeResponse(200, {"schema": [], "results": [
        {"SoftwareVendor": "ivanti", "SoftwareName": "connect_secure", "Kind": "disk", "Path": "/opt/ivanti/ics/bin/web", "Devices": 2}]})]})
    c = Client(FakeTokens(), "s", base_url=GRAPH_BASE, session=s, sleep=lambda x: None)
    assert run_named(c, run, ["evidence"]) == 0
    body = s.calls[0][2]["json"]["Query"]
    assert "DeviceTvmSoftwareEvidenceBeta" in body and '"connect_secure"' in body and '"acrobat_reader_dc"' in body
    assert run.read_json("hunt-evidence.json")["results"][0]["Path"] == "/opt/ivanti/ics/bin/web"
    assert run.manifest["sources"]["hunting.evidence"]["status"] == "ok"


def test_score_attaches_paths(tmp_path):
    from tests.test_rollup import seed
    from dva.score_cmd import compute
    from dva.config import load_scoring
    from dva.cache import IntelCache
    run = seed(tmp_path / "runs")
    run.write_json("hunt-evidence.json", {"schema": [], "results": [
        {"SoftwareVendor": "ivanti", "SoftwareName": "connect_secure", "Kind": "disk", "Path": r"C:\Program Files\Ivanti\Connect Secure\ics.exe", "Devices": 2}]})
    doc = compute(run, load_scoring(), IntelCache(tmp_path / "c", 7))
    top = doc["products"][0]
    assert top["product"] == "Connect Secure"
    assert top["paths"] == [{"path": r"%ProgramFiles%\Ivanti\Connect Secure\ics.exe", "kind": "disk", "devices": 2}]
    assert all("paths" in r for r in doc["products"])
