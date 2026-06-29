import { useState } from 'react';
import { ShieldAlert, RefreshCw, FileCode } from 'lucide-react';

export function DetectionRules() {
  const [sampleId, setSampleId] = useState('');
  const [rules, setRules] = useState<{yara_rule: string, sigma_rule: string} | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);

  const handleGenerate = async () => {
    if (!sampleId) return;
    setIsGenerating(true);
    try {
      const res = await fetch('http://localhost:8000/api/v1/detection/generate-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sample_id: sampleId })
      });
      const data = await res.json();
      setRules(data);
    } catch (err) {
      console.error(err);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <header className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <ShieldAlert className="text-primary" />
            Detection Rules Engine
          </h2>
          <p className="text-muted-foreground mt-1 text-sm">Generate rules automatically via POST /api/v1/detection/generate-rule.</p>
        </div>
      </header>

      <div className="bg-card p-4 rounded-xl border border-border flex gap-4">
        <input 
          type="text" 
          placeholder="Enter Sample UUID..." 
          value={sampleId}
          onChange={e => setSampleId(e.target.value)}
          className="flex-1 bg-background border border-border rounded-lg px-4 py-2 text-sm text-foreground focus:outline-none focus:border-primary transition-colors font-mono"
        />
        <button 
          onClick={handleGenerate}
          disabled={!sampleId || isGenerating}
          className="bg-primary/20 text-primary hover:bg-primary/30 px-6 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 border border-primary/30 disabled:opacity-50"
        >
          <RefreshCw size={16} className={isGenerating ? 'animate-spin' : ''} />
          Generate Rules
        </button>
      </div>

      {rules && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <div className="glass p-6 rounded-xl flex flex-col h-full">
            <div className="flex justify-between items-center border-b border-border pb-4 mb-4">
              <h3 className="font-semibold text-lg flex items-center gap-2">
                <FileCode size={18} className="text-yellow-500" />
                Generated YARA Rule
              </h3>
            </div>
            <pre className="bg-background border border-border rounded-lg p-4 font-mono text-sm text-muted-foreground overflow-y-auto flex-1 whitespace-pre-wrap">
              {rules.yara_rule || "// No YARA rule generated"}
            </pre>
          </div>

          <div className="glass p-6 rounded-xl flex flex-col h-full">
            <div className="flex justify-between items-center border-b border-border pb-4 mb-4">
              <h3 className="font-semibold text-lg flex items-center gap-2">
                <FileCode size={18} className="text-blue-500" />
                Generated Sigma Rule
              </h3>
            </div>
            <pre className="bg-background border border-border rounded-lg p-4 font-mono text-sm text-muted-foreground overflow-y-auto flex-1 whitespace-pre-wrap">
              {rules.sigma_rule || "# No Sigma rule generated"}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
