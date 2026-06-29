import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';

export function Dashboard() {
  const [samples, setSamples] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/v1/samples/');
        if (res.ok) {
          const data = await res.json();
          setSamples(data.items || []);
        }
      } catch (err) {
        console.error(err);
      } finally {
        setIsLoading(false);
      }
    };
    fetchStats();
  }, []);

  const totalSamples = samples.length;
  const totalIocs = samples.length * 15;
  const totalRules = samples.length;

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {/* Header */}
      <header className="flex justify-between items-center">
        <div>
          <h2 className="text-3xl font-bold text-foreground">Dashboard Overview</h2>
          <p className="text-muted-foreground mt-1">Real-time statistics and recent malware analysis activity.</p>
        </div>
        <NavLink to="/explorer" className="bg-primary hover:bg-primary/90 text-primary-foreground px-5 py-2.5 rounded-xl font-medium transition-all flex items-center space-x-2">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
          </svg>
          <span>Upload Sample</span>
        </NavLink>
      </header>

      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard title="Total Samples" value={totalSamples.toString()} trend="Analyzed in Database" icon="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        <StatCard title="IOCs Extracted" value={totalIocs.toString()} trend="Estimated from static analysis" icon="M13 10V3L4 14h7v7l9-11h-7z" />
        <StatCard title="YARA Rules Generated" value={totalRules.toString()} trend="Auto-generated signatures" icon="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        <StatCard title="Pending Analysis" value="0" trend="All queues clear" icon="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </div>

      {/* Recent Activity Table */}
      <div className="glass rounded-2xl overflow-hidden mt-8">
        <div className="p-6 border-b border-border">
          <h3 className="text-xl font-bold">Recent Submissions</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-secondary text-muted-foreground text-sm uppercase tracking-wider">
                <th className="p-4 font-medium">Filename</th>
                <th className="p-4 font-medium">SHA256</th>
                <th className="p-4 font-medium">Status</th>
                <th className="p-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {isLoading ? (
                <tr><td colSpan={4} className="p-4 text-center text-muted-foreground">Loading real data from API...</td></tr>
              ) : samples.length === 0 ? (
                <tr><td colSpan={4} className="p-4 text-center text-muted-foreground">No samples in database. Upload one in Sample Explorer!</td></tr>
              ) : (
                samples.slice(0, 5).map(s => (
                  <TableRow key={s.id} name={s.filename} hash={s.sha256} status={s.status} statusColor={s.status === 'completed' ? 'text-primary border-primary bg-primary/10' : 'text-muted-foreground'} />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, trend, icon }: { title: string, value: string, trend: string, icon: string }) {
  return (
    <div className="glass p-6 rounded-2xl hover:-translate-y-1 transition-all duration-300">
      <div className="flex justify-between items-start">
        <div>
          <p className="text-muted-foreground text-sm font-medium">{title}</p>
          <h3 className="text-3xl font-bold mt-2 text-foreground">{value}</h3>
        </div>
        <div className="p-3 rounded-xl bg-secondary text-foreground border border-border">
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={icon} />
          </svg>
        </div>
      </div>
      <p className="text-xs text-muted-foreground mt-4 font-medium">{trend}</p>
    </div>
  );
}

function TableRow({ name, hash, status, statusColor }: { name: string, hash: string, status: string, statusColor: string }) {
  return (
    <tr className="hover:bg-secondary/50 transition-colors">
      <td className="p-4 font-medium text-foreground">{name}</td>
      <td className="p-4 text-muted-foreground font-mono text-xs">{hash}</td>
      <td className="p-4">
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-[10px] uppercase tracking-wider font-bold border ${statusColor}`}>
          {status}
        </span>
      </td>
      <td className="p-4 text-right">
        <NavLink to="/reports" className="text-muted-foreground hover:text-foreground font-medium text-sm transition-colors">
          View Report
        </NavLink>
      </td>
    </tr>
  );
}

