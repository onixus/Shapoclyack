import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";

export default function Shell() {
  const { username, role, logout, canOperate } = useAuth();

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden />
          <div>
            <p className="brand-name">Octo-man</p>
            <p className="brand-sub">Scan control surface</p>
          </div>
        </div>
        <nav className="nav-links">
          <NavLink to="/" end>
            Runs
          </NavLink>
          {canOperate ? <NavLink to="/jobs">Jobs</NavLink> : null}
          {canOperate ? <NavLink to="/agents">Agents</NavLink> : null}
        </nav>
        <div className="session">
          <span>
            {username} · {role}
          </span>
          <button type="button" className="ghost-btn" onClick={logout}>
            Sign out
          </button>
        </div>
      </header>
      <main className="page">
        <Outlet />
      </main>
    </div>
  );
}
