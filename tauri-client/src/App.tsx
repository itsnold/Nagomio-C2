import { BrowserRouter as Router, Routes, Route, NavLink, Navigate } from "react-router-dom";
import { FaServer, FaLaptopCode, FaHammer, FaSyncAlt, FaTimes } from "react-icons/fa";
import { AppProvider, useAppState } from "./components/AppContext";
import { Agents } from "./pages/Agents";
import { Builder } from "./pages/Builder";
import { LiveStreamWindow } from "./pages/LiveStreamWindow";

function AppLayout() {
  const { loading, refresh, connectionState, connectionError, lastSyncAt, latencyMs, stats, notifications, dismissNotification } = useAppState();
  const connectionLabel = connectionState === "online" ? "Online" : connectionState === "syncing" ? "Syncing" : "Offline";
  const lastSyncLabel = lastSyncAt ? `Last sync ${Math.max(0, Math.floor((Date.now() - lastSyncAt) / 1000))}s ago` : "No sync yet";

  return (
<div className="app-layout">
       {/* SIDEBAR */}
       <aside className="sidebar">
         <div className="branding">
           <FaServer size={24} className="accent-color" />
           <h1>NAGOMIO</h1>
         </div>
         <nav className="nav-links">
           <NavLink to="/agents" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
             <FaLaptopCode /> Operations
           </NavLink>
           <NavLink to="/builder" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
             <FaHammer /> Payload Builder
           </NavLink>
         </nav>
         <div className="sidebar-footer">
           <button onClick={refresh} disabled={loading} className="refresh-btn">
             <FaSyncAlt className={loading ? "spin" : ""} /> {loading ? "Syncing..." : "Refresh"}
           </button>
         </div>
       </aside>

       {/* MAIN CONTENT */}
       <div className="main-wrapper">
         <header className="topbar">
           <div className="ops-status-bar" title={connectionError || undefined}>
             <div className={`connection-chip ${connectionState}`}>
               <span className={`pulse-dot ${connectionState}`}></span>
               <strong>{connectionLabel}</strong>
             </div>
             <div className="ops-stat"><span>{stats.agentsTotal}</span> agents</div>
             <div className="ops-stat good"><span>{stats.agentsOnline}</span> online</div>
             <div className="ops-stat warn"><span>{stats.agentsStale}</span> stale</div>
             <div className="ops-stat muted"><span>{stats.agentsOffline}</span> offline</div>
             <div className="ops-divider" />
             <div className="ops-stat muted"><span>{stats.tasksQueued}</span> queued</div>
             <div className="ops-stat warn"><span>{stats.tasksDispatched}</span> running</div>
             <div className="ops-stat good"><span>{stats.tasksCompleted}</span> done</div>
             <div className="ops-stat bad"><span>{stats.tasksFailed}</span> failed</div>
           </div>
           <div className="sync-meta">
             {latencyMs !== null ? <span>{latencyMs}ms</span> : null}
             <span>{lastSyncLabel}</span>
           </div>
         </header>

         <div className="toast-stack" aria-live="polite" aria-atomic="false">
           {notifications.map((notification) => (
             <div key={notification.id} className={`toast toast-${notification.kind}`}>
               <div>
                 <strong>{notification.title}</strong>
                 {notification.detail ? <p>{notification.detail}</p> : null}
               </div>
               <button type="button" onClick={() => dismissNotification(notification.id)} aria-label="Dismiss notification">
                 <FaTimes />
               </button>
             </div>
           ))}
         </div>

         <main className="content">
          <Routes>
            <Route path="/" element={<Navigate to="/agents" replace />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/tasks" element={<Navigate to="/agents" replace />} />
            <Route path="/builder" element={<Builder />} />
            <Route path="*" element={<Navigate to="/agents" replace />} />
          </Routes>
         </main>
       </div>
     </div>
   );
 }

 export function App() {
   return (
     <AppProvider>
      <Router>
        <Routes>
          <Route path="/live" element={<LiveStreamWindow />} />
          <Route path="*" element={<AppLayout />} />
        </Routes>
      </Router>
     </AppProvider>
   );
 }
