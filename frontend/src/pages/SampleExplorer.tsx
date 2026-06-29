import { useState, type FormEvent } from 'react';
import { FileSearch, Clock, Upload, AlertCircle } from 'lucide-react';

export function SampleExplorer() {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleUpload = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setIsUploading(true);
    setErrorMsg(null);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:8000/api/v1/scan/file', {
        method: 'POST',
        body: formData,
      });
      
      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`);
      }
      
      const data = await response.json();
      setScanResult(data);
    } catch (err: any) {
      console.error(err);
      setErrorMsg("Failed to reach the backend API. Ensure Docker is running and FastAPI is healthy.");
    } finally {
      setIsUploading(false);
      setFile(null);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <header>
        <h2 className="text-2xl font-bold text-foreground">Sample Explorer</h2>
        <p className="text-muted-foreground mt-1 text-sm">Upload a new sample for immediate pipeline scanning.</p>
      </header>

      <div className="bg-card rounded-xl border border-border p-6 mb-6">
        <form onSubmit={handleUpload} className="flex gap-4 items-center">
          <input 
            type="file" 
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            className="flex-1 bg-background border border-border rounded-lg px-4 py-2 text-sm text-foreground file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-primary/20 file:text-primary hover:file:bg-primary/30"
          />
          <button 
            type="submit" 
            disabled={!file || isUploading}
            className="bg-primary hover:bg-primary/90 text-primary-foreground px-6 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            {isUploading ? <Clock className="animate-spin" size={18} /> : <Upload size={18} />}
            <span>{isUploading ? 'Scanning Pipeline...' : 'Upload Sample'}</span>
          </button>
        </form>
        {errorMsg && (
          <div className="mt-4 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-sm rounded-lg flex items-center gap-2">
            <AlertCircle size={16} />
            {errorMsg}
          </div>
        )}
      </div>

      {scanResult && (
        <div className={`p-6 rounded-xl border ${scanResult.classification === 'MALICIOUS' ? 'bg-destructive/10 border-destructive/30' : 'bg-primary/5 border-primary/20'}`}>
          <div className="flex items-center gap-2 mb-4">
            <AlertCircle className={scanResult.classification === 'MALICIOUS' ? 'text-destructive' : 'text-primary'} />
            <h3 className="text-xl font-bold">{scanResult.classification}</h3>
            <span className="ml-auto font-mono text-sm text-muted-foreground">Score: {scanResult.risk_score}/100</span>
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm font-mono text-muted-foreground">
            <div>SHA256: {scanResult.sha256}</div>
            <div>YARA Matches: {scanResult.yara_matches.join(', ') || 'None'}</div>
          </div>
        </div>
      )}

      <div className="bg-card rounded-xl border border-border overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-secondary text-muted-foreground text-xs uppercase tracking-wider">
              <th className="p-4 font-medium">Filename</th>
              <th className="p-4 font-medium">SHA256 Hash</th>
              <th className="p-4 font-medium">Risk Score</th>
              <th className="p-4 font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border text-sm">
            {scanResult && (
              <SampleRow 
                name={scanResult.sample_id} 
                hash={scanResult.sha256} 
                score={scanResult.risk_score}
                status={scanResult.classification}
              />
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SampleRow({ name, hash, score, status }: { name: string, hash: string, score: number, status: string }) {
  return (
    <tr className="hover:bg-secondary/50 transition-colors group cursor-pointer">
      <td className="p-4 font-medium text-primary flex items-center gap-2">
        <FileSearch size={16} className="text-muted-foreground group-hover:text-primary transition-colors" />
        Sample {name.substring(0,8)}
      </td>
      <td className="p-4 text-muted-foreground font-mono">{hash}</td>
      <td className="p-4 text-muted-foreground">{score}</td>
      <td className="p-4">
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${status === 'MALICIOUS' ? 'bg-destructive/20 text-destructive border-destructive/30' : 'bg-primary/20 text-primary border-primary/30'}`}>
          {status}
        </span>
      </td>
    </tr>
  );
}

