import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./lib/auth";
import { Layout } from "./components/Layout";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { GraphView } from "./pages/GraphView";
import { HuntsPage } from "./pages/HuntsPage";
import { IncidentPage } from "./pages/IncidentPage";
import { ContainmentPage } from "./pages/ContainmentPage";
import { PassportVerify } from "./pages/PassportVerify";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth();
  if (isLoading) return <div style={{ padding: "2rem", textAlign: "center" }}>Loading session...</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

export function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/graph"
            element={
              <ProtectedRoute>
                <GraphView />
              </ProtectedRoute>
            }
          />
          <Route
            path="/hunts"
            element={
              <ProtectedRoute>
                <HuntsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/incidents"
            element={
              <ProtectedRoute>
                <IncidentPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/containment"
            element={
              <ProtectedRoute>
                <ContainmentPage />
              </ProtectedRoute>
            }
          />
          {/* Public verification route accessible without auth */}
          <Route
            path="/verify"
            element={
              <Layout>
                <PassportVerify />
              </Layout>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
