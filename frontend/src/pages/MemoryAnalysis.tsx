import { useState } from 'react';
import { Cpu, Search } from 'lucide-react';

export function MemoryAnalysis() {
  const [sampleId, setSampleId] = useState('');
  const [result, setResult] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  const fetchAnalysis = async () => {
    if (!sampleId) return;
    setIsLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/api/v1/memory/${sampleId}`);
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
            <Cpu className="text-foreground" />
            Memory Forensics
          </h2>
          <p className="text-muted-foreground mt-1 text-sm">Analyze Volatility 3 outputs for process injection and rootkits.</p>
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
          className="bg-primary hover:bg-primary/90 text-primary-foreground px-6 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 disabled:opacity-50"
        >
          <Search size={16} />
          <span>{isLoading ? 'Fetching...' : 'Analyze'}</span>
        </button>
      </div>

      {result && (
        <div className="glass p-6 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between border-b border-secondary pb-4 mb-4">
            <h3 className="font-semibold text-lg">Process Tree</h3>
          </div>

          <div className="font-mono text-sm space-y-2 text-muted-foreground bg-background p-4 rounded border border-secondary overflow-x-auto">
            {result.processes && result.processes.length > 0 ? result.processes.map((p: any, idx: number) => (
              <div key={idx} className="flex items-center gap-4 hover:bg-secondary/50 px-2 py-1 rounded">
                <span className="w-16">{p.pid}</span>
                <span className="text-foreground">{p.name}</span>
              </div>
            )) : (
              <div>No process tree data available.</div>
            )}
            
            {result.injected_processes && result.injected_processes.length > 0 && (
              <div className="mt-6 border-t border-destructive/20 pt-4">
                <h4 className="text-destructive font-bold mb-2">Injected / Hidden Processes Detected:</h4>
                {result.injected_processes.map((p: any, idx: number) => (
                  <div key={idx} className="flex items-center gap-4 bg-destructive/10 border border-destructive/20 px-2 py-1 rounded mb-2">
                    <span className="text-destructive font-bold">{p}</span>
                    <span className="text-xs text-destructive">Unlinked Process Block!</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
