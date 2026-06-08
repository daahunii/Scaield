import { useEffect, useMemo, useState } from "react";
import { AppShell } from "./components/layout/AppShell.jsx";
import { ArchiveView } from "./features/archive/ArchiveView.jsx";
import { ProfileView } from "./features/profile/ProfileView.jsx";
import { ScannerView } from "./features/scanner/ScannerView.jsx";
import { useScanner } from "./features/scanner/hooks/useScanner.js";
import { SettingsView } from "./features/settings/SettingsView.jsx";

function App() {
  const [activeTab, setActiveTab] = useState("scanner");
  const [scanDepth, setScanDepth] = useState(3);
  const [sessionCookie, setSessionCookie] = useState(
    "security=impossible; PHPSESSID=mock",
  );
  const [customHeader, setCustomHeader] = useState("X-Scanner: Scaield-LLM");

  const scanner = useScanner({ setActiveTab });

  const targetDomain = useMemo(() => {
    try {
      const parsed = new URL(scanner.targetUrl);
      return parsed.host || "localhost:8080";
    } catch {
      return "localhost:8080";
    }
  }, [scanner.targetUrl]);

  const customHeaderParsed = useMemo(() => {
    if (!customHeader) return null;

    const splitIndex = customHeader.indexOf(":");
    if (splitIndex === -1) {
      return { name: "Custom-Header", value: customHeader };
    }

    return {
      name: customHeader.substring(0, splitIndex).trim(),
      value: customHeader.substring(splitIndex + 1).trim(),
    };
  }, [customHeader]);

  useEffect(() => {
    if (activeTab === "archive") {
      scanner.fetchArchiveList();
    }
  }, [activeTab]);

  return (
    <AppShell activeTab={activeTab} onTabChange={setActiveTab}>
      {activeTab === "scanner" && <ScannerView scanner={scanner} />}

      {activeTab === "archive" && (
        <ArchiveView
          archiveList={scanner.archiveList}
          loadingArchive={scanner.loadingArchive}
          onLoadArchiveScan={scanner.handleLoadArchiveScan}
        />
      )}

      {activeTab === "settings" && (
        <SettingsView
          targetDomain={targetDomain}
          scanDepth={scanDepth}
          setScanDepth={setScanDepth}
          sessionCookie={sessionCookie}
          setSessionCookie={setSessionCookie}
          customHeader={customHeader}
          setCustomHeader={setCustomHeader}
          customHeaderParsed={customHeaderParsed}
        />
      )}

      {activeTab === "profile" && <ProfileView />}
    </AppShell>
  );
}

export default App;
