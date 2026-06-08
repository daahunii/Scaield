import { Activity, Folder, Settings, User, Zap } from "lucide-react";

const navItems = [
  { id: "scanner", label: "보안 스캐너", icon: Activity },
  { id: "archive", label: "리포트 보관함", icon: Folder },
  { id: "settings", label: "스캔 설정", icon: Settings },
  { id: "profile", label: "프로필", icon: User },
];

export function Sidebar({ activeTab, onTabChange }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-container">
        <div className="sidebar-logo">
          <div className="sidebar-logo-glyph">S</div>
          <span className="sidebar-logo-text">Scaield</span>
        </div>

        <nav className="sidebar-menu" aria-label="사이드 메뉴">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                className={`sidebar-item ${isActive ? "active" : ""}`}
                onClick={() => onTabChange(item.id)}
                type="button"
              >
                <Icon size={18} />
                <span>{item.label}</span>
                {isActive && <div className="sidebar-item-active-bar" />}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="sidebar-profile">
        <div className="sidebar-avatar">DK</div>
        <div className="sidebar-profile-info">
          <span className="sidebar-profile-name">Dongkeun</span>
          <span className="sidebar-profile-role">
            <Zap size={11} /> Enterprise
          </span>
        </div>
      </div>
    </aside>
  );
}
