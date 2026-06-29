import { BrowserRouter as Router, Routes, Route } from "react-router-dom"
import { Layout } from "./components/Layout"
import { Dashboard } from "./pages/Dashboard"
import { SampleExplorer } from "./pages/SampleExplorer"
import { StaticAnalysis } from "./pages/StaticAnalysis"
import { MemoryAnalysis } from "./pages/MemoryAnalysis"
import { DetectionRules } from "./pages/DetectionRules"
import { ThreatReports } from "./pages/ThreatReports"

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/explorer" element={<SampleExplorer />} />
          <Route path="/static" element={<StaticAnalysis />} />
          <Route path="/memory" element={<MemoryAnalysis />} />
          <Route path="/rules" element={<DetectionRules />} />
          <Route path="/reports" element={<ThreatReports />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App
