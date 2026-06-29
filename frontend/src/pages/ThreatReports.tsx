import { useState } from 'react';
import { Activity, Search } from 'lucide-react';

export function ThreatReports() {
  const [hash, setHash] = useState('');
  const [report, setReport] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  const fetchReport = async () => {
    if (!hash) return;
    setIsLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/report/${hash}`);
      const data = await res.json();
      setReport(data);
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <header>
        <h2 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <Activity className="text-primary" />
          Threat Intelligence Reports
        </h2>
        <p className="text-muted-foreground mt-1 text-sm">Fetch full forensic report via GET /api/v1/report/&#123;hash&#125;.</p>
      </header>

      <div className="bg-card p-4 rounded-xl border border-border flex gap-4">
        <input 
          type="text" 
          placeholder="Enter SHA256 Hash..." 
          value={hash}
          onChange={e => setHash(e.target.value)}
          className="flex-1 bg-background border border-border rounded-lg px-4 py-2 text-sm text-foreground focus:outline-none focus:border-primary transition-colors font-mono"
        />
        <button 
          onClick={fetchReport}
          disabled={!hash || isLoading}
          className="bg-primary hover:bg-primary/90 text-primary-foreground px-6 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 disabled:opacity-50"
        >
          <Search size={16} />
          {isLoading ? 'Fetching...' : 'Fetch Report'}
        </button>
      </div>

      {report && (
        <div className="glass p-6 rounded-xl border border-primary/30">
          <div className="flex justify-between items-start mb-4">
            <div>
              <h3 className="font-bold text-xl text-primary">Executive Summary: {report.sample_id}</h3>
            </div>
            <span className="px-3 py-1 bg-destructive/10 text-destructive font-bold rounded-full text-xs border border-destructive/20">
              Score: {report.overall_score || 0}/100
            </span>
          </div>
          <p className="text-sm text-foreground/80 leading-relaxed mb-6 font-mono whitespace-pre-wrap">
            {JSON.stringify(report.summary, null, 2)}
          </p>
        </div>
      )}
    </div>
  );
}
