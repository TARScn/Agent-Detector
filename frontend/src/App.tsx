import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AppShell } from "./layout/AppShell";
import { OverviewPage } from "./pages/OverviewPage";
import { AssetsPage } from "./pages/AssetsPage";
import { AssetDetailPage } from "./pages/AssetDetailPage";
import { EventsPage } from "./pages/EventsPage";
import { AlertsPage } from "./pages/AlertsPage";
import { PoliciesPage } from "./pages/PoliciesPage";
import { CollectorsPage } from "./pages/CollectorsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { EmptyState, PageHeader } from "./components/ui";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: true,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<Navigate to="/overview" replace />} />
            <Route path="/overview" element={<OverviewPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/assets/:entityId" element={<AssetDetailPage />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/collectors" element={<CollectorsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route
              path="*"
              element={
                <div className="page">
                  <PageHeader title="页面不存在" />
                  <EmptyState title="404" />
                </div>
              }
            />
          </Route>
        </Routes>
      </HashRouter>
    </QueryClientProvider>
  );
}