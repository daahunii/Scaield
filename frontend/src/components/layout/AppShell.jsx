import { Footer } from "./Footer.jsx";
import { Sidebar } from "./Sidebar.jsx";

export function AppShell({ activeTab, onTabChange, children }) {
  return (
    <div className="app-shell">
      <Sidebar activeTab={activeTab} onTabChange={onTabChange} />
      <main className="main-workspace">
        <div className="gradient-mesh-backdrop" aria-hidden="true" />
        {children}
        <Footer />
      </main>
    </div>
  );
}
