import React, { useState } from 'react';
import { FileCode, Shield, Terminal, Search } from 'lucide-react';

export function StaticAnalysis() {
  const [sampleId, setSampleId] = useState('');
  const [result, setResult] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  const fetchAnalysis = async () => {
    if (!sampleId) return;
    setIsLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/analysis/static/${sampleId}`);
      if (res.ok) {
        const data = await res.json();
        setResult(data);
      } else {
        setResult(null);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <header className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <FileCode className="text-foreground" />
            Static Analysis
          </h2>
          <p className="text-muted mt-1 text-sm">Reverse engineer binary structures and extract indicators.</p>
        </div>
      </header>

      <div className="bg-card p-4 rounded-xl border border-secondary flex gap-4">
        <input 
          type="text" 
          placeholder="Enter Sample UUID..." 
          value={sampleId}
          onChange={e => setSampleId(e.target.value)}
          className="flex-1 bg-background border border-secondary rounded-lg px-4 py-2 text-sm text-foreground focus:outline-none focus:border-muted transition-colors font-mono"
        />
        <button 
          onClick={fetchAnalysis}
          disabled={!sampleId || isLoading}
          className="bg-white hover:bg-neutral-200 text-black px-6 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 disabled:opacity-50"
        >
          <Search size={16} className="text-black" />
          <span className="text-black">{isLoading ? 'Fetching...' : 'Analyze'}</span>
        </button>
      </div>

      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <div className="glass p-6 rounded-xl">
              <h3 className="font-semibold text-lg border-b border-secondary pb-3 mb-4">PE Headers</h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                {Object.entries(result.headers || {}).map(([key, value]) => (
                  <div key={key}><span className="text-muted">{key}:</span> <span className="font-mono text-foreground ml-2">{String(value)}</span></div>
                ))}
              </div>
            </div>

            <div className="glass p-6 rounded-xl">
              <h3 className="font-semibold text-lg border-b border-secondary pb-3 mb-4">Sections</h3>
              <table className="w-full text-left text-sm">
                <thead className="text-muted border-b border-secondary">
                  <tr>
                    <th className="pb-2">Name</th>
                    <th className="pb-2">Virtual Size</th>
                    <th className="pb-2">Entropy</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-secondary">
                  {(result.sections || []).map((sec: any, idx: number) => (
                    <tr key={idx}>
                      <td className="py-3 font-mono text-foreground">{sec.name}</td>
                      <td className="py-3 font-mono">{sec.virtual_size}</td>
                      <td className={`py-3 ${sec.entropy > 7 ? 'text-destructive font-bold' : 'text-foreground'}`}>{sec.entropy}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="space-y-6">
            <div className="glass p-6 rounded-xl border border-destructive/20 bg-destructive/5">
              <h3 className="font-semibold text-lg text-destructive flex items-center gap-2 mb-4">
                <Shield size={18} />
                Heuristics
              </h3>
              <ul className="space-y-3 text-sm text-muted">
                {(result.heuristics || []).map((h: any, idx: number) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-destructive mt-0.5">•</span>
                    {h.description}
                  </li>
                ))}
                {(!result.heuristics || result.heuristics.length === 0) && (
                  <li>No heuristics matched.</li>
                )}
              </ul>
            </div>

            <div className="glass p-6 rounded-xl">
              <h3 className="font-semibold text-lg flex items-center gap-2 mb-4">
                <Terminal size={18} />
                Extracted Strings
              </h3>
              <div className="bg-background border border-secondary p-3 rounded font-mono text-xs text-muted h-64 overflow-y-auto">
                {(result.strings || []).map((s: string, idx: number) => (
                  <div key={idx} className="truncate">{s}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
