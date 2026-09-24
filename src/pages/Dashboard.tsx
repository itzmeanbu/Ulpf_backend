import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileText, AlertTriangle, Activity, Server } from 'lucide-react';
import PageContainer from '../components/layout/PageContainer';
import StatCard from '../components/dashboard/StatCard';
import RecentEvents from '../components/dashboard/RecentEvents';
import AlertSummary from '../components/dashboard/AlertSummary';
import Loading from '../components/common/Loading';
import ErrorMessage from '../components/common/ErrorMessage';
import logService from '../services/logService';
import alertService from '../services/alertService';

export default function Dashboard() {
  const navigate = useNavigate();
  const alertSummaryRef = useRef<HTMLDivElement>(null);
  const [logStats, setLogStats] = useState<any>(null);
  const [alertSummary, setAlertSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [logData, alertData] = await Promise.all([
        logService.getLogStats(),
        alertService.getAlertSummary(),
      ]);
      setLogStats(logData);
      setAlertSummary(alertData);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  if (loading) return <Loading message="Loading dashboard..." />;
  if (error) return <ErrorMessage message={error} onRetry={fetchData} />;

  return (
    <PageContainer>
      <div className="dashboard">
        <div className="stats-grid">
          <StatCard
            title="Total Logs"
            value={logStats?.total?.toLocaleString() || '0'}
            icon={FileText}
            color="blue"
            trend={12}
            trendLabel="vs last week"
            onClick={() => navigate('/logs')}
          />
          <StatCard
            title="Active Alerts"
            value={alertSummary?.active || '0'}
            icon={AlertTriangle}
            color="red"
            trend={-5}
            trendLabel="vs last week"
            onClick={() => alertSummaryRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
          />
          <StatCard
            title="Critical Events"
            value={logStats?.critical || '0'}
            icon={Activity}
            color="yellow"
            trend={3}
            trendLabel="vs last week"
            onClick={() => navigate('/logs')}
          />
          <StatCard
            title="Log Sources"
            value={logStats?.sources?.length || '0'}
            icon={Server}
            color="green"
          />
        </div>

        <div className="dashboard-grid">
          <RecentEvents events={logStats?.recentEvents || []} />
          <div ref={alertSummaryRef}>
            <AlertSummary summary={alertSummary} />
          </div>
        </div>
      </div>
    </PageContainer>
  );
}
