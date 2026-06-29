import React, { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { ThemeToggle } from './ThemeToggle';
import { Activity, Database, FileCode, Cpu, ShieldAlert, BarChart3 } from 'lucide-react';

interface LayoutProps {
  children: ReactNode;
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="flex h-screen w-full bg-background overflow-hidden text-foreground transition-colors duration-300">
      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 bg-card border-r border-white/10 flex flex-col h-full relative z-20 transition-colors duration-300">
        <div className="p-6 border-b border-white/10 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-wider text-primary">MAP</h1>
            <p className="text-[10px] text-muted mt-1 uppercase font-semibold">Malware Analysis Platform</p>
          </div>
        </div>
        
        <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
          <NavItem to="/" label="Dashboard" icon={<BarChart3 size={18} />} />
          <NavItem to="/explorer" label="Sample Explorer" icon={<Database size={18} />} />
          <NavItem to="/static" label="Static Analysis" icon={<FileCode size={18} />} />
          <NavItem to="/memory" label="Memory Forensics" icon={<Cpu size={18} />} />
          <NavItem to="/rules" label="Detection Rules" icon={<ShieldAlert size={18} />} />
          <NavItem to="/reports" label="Threat Reports" icon={<Activity size={18} />} />
        </nav>
        
        <div className="p-4 border-t border-white/10 text-[10px] text-muted text-center flex justify-center items-center font-mono uppercase tracking-wider">
          <span>MAP v1.0.0 • Made by @prxcode</span>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col relative overflow-hidden bg-background transition-colors duration-300">
        {/* Header Strip with Theme Toggle */}
        <div className="h-14 border-b border-white/5 flex items-center justify-end px-6">
          <ThemeToggle />
        </div>
        
        <div className="flex-1 overflow-y-auto p-8 relative z-10">
          {children}
        </div>
      </main>
    </div>
  );
}

function NavItem({ label, icon, to }: { label: string, icon: React.ReactNode, to: string }) {
  return (
    <NavLink 
      to={to} 
      className={({ isActive }) => `flex items-center space-x-3 px-3 py-2.5 rounded-lg transition-all duration-200 ${
        isActive 
          ? 'bg-primary/10 text-primary font-medium' 
          : 'text-muted hover:bg-white/5 hover:text-foreground'
      }`}
    >
      {icon}
      <span className="text-sm">{label}</span>
    </NavLink>
  );
}
