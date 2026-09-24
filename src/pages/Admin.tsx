import React, { useState, useEffect, useCallback } from 'react';
import { Trash2 } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import PageContainer from '../components/layout/PageContainer';
import Loading from '../components/common/Loading';
import ActionButton from '../components/common/ActionButton';
import RecycleBinPanel, { RecycleBinConfig } from '../components/common/RecycleBinPanel';
import adminService from '../services/adminService';
import logService from '../services/logService';
import Alerts from './Alerts';
import Logs from './Logs';
import AdminSettings from './AdminSettings';

const TABS = ['Overview', 'Users', 'Access requests', 'Logs', 'Alerts', 'Log sources', 'Log access', 'Recycle Bin', 'Audit log', 'Reports', 'Settings'];
// There is only one admin, set in the server environment, so it is not listed here.
const ROLES = ['pending', 'viewer', 'analyst'];

// Small helper: loads data when the tab opens.
function useLoad<T = any>(fn: () => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const load = useCallback(async () => {
    try { setError(''); setData(await fn()); } catch (e: any) { setError(e.message); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fn]);
  useEffect(() => { load(); }, [load]);
  return { data, error, reload: load, setData };
}

function Overview() {
  const { data, error } = useLoad(adminService.getOverview);
  if (error) return <div className="pg-msg err">{error}</div>;
  if (!data) return <Loading />;
  const items: [string, any][] = [
    ['Total users', data.totalUsers], ['Pending access requests', data.pendingAccessRequests],
    ['Logs processed', data.logsProcessed], ['Active sources', data.activeSources],
    ['Open security alerts', data.openSecurityAlerts],
  ];
  return <div className="pg-cards">{items.map(([l, n]) => <div className="pg-card" key={l}><div className="num">{n}</div><div className="lbl">{l}</div></div>)}</div>;
}

function Users() {
  const { data, error, reload } = useLoad<any[]>(adminService.getUsers);
  const [msg, setMsg] = useState<{ type: string; text: string } | null>(null);
  const run = async (fn: () => Promise<any>, okText: string) => {
    try { setMsg(null); await fn(); setMsg({ type: 'ok', text: okText }); reload(); }
    catch (e: any) { setMsg({ type: 'err', text: e.message }); }
  };
  if (error) return <div className="pg-msg err">{error}</div>;
  if (!data) return <Loading />;
  return (
    <div className="pg-stack">
      {msg && <div className={`pg-msg ${msg.type}`}>{msg.text}</div>}
      <div className="panel pg-table-wrap">
        <table className="pg-table">
          <thead><tr><th>Email</th><th>Role</th><th>Sensitive</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            {data.map((u) => u.role === 'admin' ? (
              <tr key={u.id}>
                <td>{u.email}</td>
                <td><span className="badge badge-info">admin</span></td>
                <td>Yes</td>
                <td><span className="badge badge-success">permanent</span></td>
                <td className="pg-muted">Only changed in the server settings</td>
              </tr>
            ) : (
              <tr key={u.id}>
                <td>{u.email}</td>
                <td>
                  <select className="pg-select" value={u.role} onChange={(e) => run(() => adminService.updateUserRole(u.id, e.target.value), 'Role updated.')}>
                    {ROLES.map((r) => <option key={r}>{r}</option>)}
                  </select>
                </td>
                <td>{u.sensitive_access ? <ActionButton size="small" variant="ghost" onClick={() => run(() => adminService.revokeSensitive(u.id), 'Sensitive access revoked.')}>Revoke</ActionButton> : 'No'}</td>
                <td><span className={`badge ${u.disabled ? 'badge-critical' : u.role === 'pending' ? 'badge-warning' : 'badge-success'}`}>{u.disabled ? 'disabled' : u.role === 'pending' ? 'awaiting approval' : 'active'}</span></td>
                <td>
                  <div className="pg-row">
                    {u.role === 'pending' && <ActionButton size="small" onClick={() => run(() => adminService.updateUserRole(u.id, 'viewer'), 'User approved as viewer.')}>Approve</ActionButton>}
                    {u.disabled
                      ? <ActionButton size="small" variant="ghost" onClick={() => run(() => adminService.enableUser(u.id), 'User enabled.')}>Enable</ActionButton>
                      : <ActionButton size="small" variant="ghost" onClick={() => run(() => adminService.disableUser(u.id), 'User disabled.')}>Disable</ActionButton>}
                    <ActionButton size="small" variant="danger" onClick={() => window.confirm(`Move ${u.email} to the recycle bin? You can restore it later from Admin > Recycle Bin.`) && run(() => adminService.deleteUser(u.id), 'Account moved to the recycle bin.')}>Delete</ActionButton>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AccessRequests() {
  const { data, error, reload } = useLoad<any[]>(adminService.getAccessRequests);
  const [msg, setMsg] = useState<{ type: string; text: string } | null>(null);
  const run = async (fn: () => Promise<any>, t: string) => { try { setMsg(null); await fn(); setMsg({ type: 'ok', text: t }); reload(); } catch (e: any) { setMsg({ type: 'err', text: e.message }); } };
  if (error) return <div className="pg-msg err">{error}</div>;
  if (!data) return <Loading />;
  return (
    <div className="pg-stack">
      {msg && <div className={`pg-msg ${msg.type}`}>{msg.text}</div>}
      <div className="panel pg-table-wrap">
        {data.length === 0 ? <div className="pg-empty">No requests.</div> : (
          <table className="pg-table">
            <thead><tr><th>User</th><th>Asking for</th><th>Requested</th><th>Status</th><th></th></tr></thead>
            <tbody>{data.map((r) => (
              <tr key={r.id}>
                <td>{r.email}</td><td>{r.type === 'upload' ? 'Upload access (becomes analyst)' : 'Sensitive log access'}</td><td>{new Date(r.created_at).toLocaleString()}</td><td>{r.status}</td>
                <td>{r.status === 'pending' && <div className="pg-row">
                  <ActionButton size="small" onClick={() => run(() => adminService.approveAccessRequest(r.id), 'Approved.')}>Approve</ActionButton>
                  <ActionButton size="small" variant="danger" onClick={() => run(() => adminService.rejectAccessRequest(r.id), 'Rejected.')}>Reject</ActionButton>
                </div>}</td>
              </tr>))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Sources() {
  const { data, error, reload } = useLoad<any[]>(adminService.getSources);
  const [name, setName] = useState('');
  const [vendor, setVendor] = useState('');
  const [msg, setMsg] = useState<{ type: string; text: string } | null>(null);
  const run = async (fn: () => Promise<any>, t: string) => { try { setMsg(null); await fn(); setMsg({ type: 'ok', text: t }); reload(); } catch (e: any) { setMsg({ type: 'err', text: e.message }); } };
  if (error) return <div className="pg-msg err">{error}</div>;
  if (!data) return <Loading />;
  return (
    <div className="pg-stack">
      <p className="pg-muted">
        A source is the company or system your logs come from (for example Cisco, Fortinet, Linux, Windows).
        This list is for your records. The On/Off switch is saved, but it does not block uploads yet.
      </p>
      {msg && <div className={`pg-msg ${msg.type}`}>{msg.text}</div>}
      <div className="pg-row">
        <input className="pg-input" placeholder="Source name" value={name} onChange={(e) => setName(e.target.value)} />
        <input className="pg-input" placeholder="Vendor (optional)" value={vendor} onChange={(e) => setVendor(e.target.value)} />
        <ActionButton disabled={!name.trim()} onClick={() => run(async () => { await adminService.addSource(name.trim(), vendor.trim() || undefined); setName(''); setVendor(''); }, 'Source added.')}>Add source</ActionButton>
      </div>
      <div className="panel pg-table-wrap">
        <table className="pg-table">
          <thead><tr><th>Name</th><th>Vendor</th><th>Enabled</th><th></th></tr></thead>
          <tbody>{data.map((s) => (
            <tr key={s.id}><td>{s.name}</td><td>{s.vendor || '-'}</td>
              <td><label className="pg-toggle"><input type="checkbox" checked={s.enabled} onChange={(e) => run(() => adminService.updateSource(s.id, { enabled: e.target.checked }), 'Source updated.')} />{s.enabled ? 'On' : 'Off'}</label></td>
              <td><ActionButton size="small" variant="danger" onClick={() => window.confirm(`Move "${s.name}" to the recycle bin?`) && run(() => adminService.deleteSource(s.id), 'Source moved to the recycle bin.')}><Trash2 size={14} /></ActionButton></td>
            </tr>))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function LogAccess() {
  const access = useLoad<any[]>(adminService.getLogAccess);
  const sources = useLoad<any[]>(adminService.getSources);
  const [msg, setMsg] = useState<{ type: string; text: string } | null>(null);
  if (access.error || sources.error) return <div className="pg-msg err">{access.error || sources.error}</div>;
  if (!access.data || !sources.data) return <Loading />;
  const toggle = async (u: any, cat: string, on: boolean) => {
    const next = on ? [...u.categories, cat] : u.categories.filter((c: string) => c !== cat);
    try { setMsg(null); await adminService.setLogAccess(u.userId, next); setMsg({ type: 'ok', text: 'Saved.' }); access.reload(); }
    catch (e: any) { setMsg({ type: 'err', text: e.message }); }
  };
  return (
    <div className="pg-stack">
      <p className="pg-muted">
        Tick which kinds of logs each user should be allowed to see. Your ticks are saved,
        but they are not enforced yet: every approved user can still see all (masked) logs.
      </p>
      {msg && <div className={`pg-msg ${msg.type}`}>{msg.text}</div>}
      <div className="panel pg-table-wrap">
        <table className="pg-table">
          <thead><tr><th>User</th>{sources.data.map((s) => <th key={s.id}>{s.name}</th>)}</tr></thead>
          <tbody>{access.data.map((u) => (
            <tr key={u.userId}><td>{u.email}</td>
              {sources.data!.map((s) => <td key={s.id}><input type="checkbox" checked={u.categories.includes(s.name)} onChange={(e) => toggle(u, s.name, e.target.checked)} /></td>)}
            </tr>))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Audit() {
  const { data, error } = useLoad<any[]>(adminService.getAudit);
  if (error) return <div className="pg-msg err">{error}</div>;
  if (!data) return <Loading />;
  return (
    <div className="panel pg-table-wrap">
      {data.length === 0 ? <div className="pg-empty">Nothing recorded yet.</div> : (
        <table className="pg-table">
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr></thead>
          <tbody>{data.map((a) => (
            <tr key={a.id}><td>{new Date(a.created_at).toLocaleString()}</td><td>{a.user_email || '-'}</td><td>{a.action}</td>
              <td className="pg-muted">{a.details ? JSON.stringify(a.details) : ''}</td></tr>))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Reports() {
  const [type, setType] = useState('daily');
  const [report, setReport] = useState<any>(null);
  const [error, setError] = useState('');
  const run = async (t: string) => {
    setType(t); setReport(null); setError('');
    try { setReport(await adminService.getReport(t)); } catch (e: any) { setError(e.message); }
  };
  useEffect(() => { run('daily'); }, []);
  return (
    <div className="pg-stack">
      <div className="pg-row">
        {['daily', 'weekly', 'security', 'user-activity'].map((t) => (
          <button key={t} className={`pg-btn ${type === t ? '' : 'ghost'}`} onClick={() => run(t)}>{t}</button>
        ))}
      </div>
      {error && <div className="pg-msg err">{error}</div>}
      {!report && !error && <Loading />}
      {report && <pre className="pg-pre" style={{ maxHeight: 420 }}>{JSON.stringify(report, null, 2)}</pre>}
    </div>
  );
}

/* ---------------------------------------------------------------------- */
/* Recycle Bin - "many pages" of it: one per deletable category.           */
/* ---------------------------------------------------------------------- */

const RECYCLE_PAGES = ['Logs', 'Accounts', 'Alerts', 'Log sources'];

const logsRecycleConfig: RecycleBinConfig = {
  title: 'Logs',
  emptyMessage: 'No deleted logs.',
  columns: [
    { header: 'Deleted', cell: (l) => (l.deletedAt ? new Date(l.deletedAt).toLocaleString() : '-') },
    { header: 'Vendor', cell: (l) => l.vendor || '-' },
    { header: 'Summary', cell: (l) => l.readableSummary || l.action || '-' },
    { header: 'Deleted by', cell: (l) => l.deletedByEmail || '-' },
  ],
  getId: (l) => l.eventId,
  load: () => logService.getRecycleBin(),
  restore: (id) => logService.restoreLog(id),
  restoreBulk: (ids) => logService.restoreLogsBulk(ids),
  permanentDelete: (id) => logService.permanentlyDeleteLog(id),
  permanentDeleteBulk: (ids) => logService.permanentlyDeleteLogsBulk(ids),
  empty: () => logService.emptyRecycleBin(),
};

const accountsRecycleConfig: RecycleBinConfig = {
  title: 'Accounts',
  emptyMessage: 'No deleted accounts.',
  columns: [
    { header: 'Deleted', cell: (u) => (u.deleted_at ? new Date(u.deleted_at).toLocaleString() : '-') },
    { header: 'Email', cell: (u) => u.email },
    { header: 'Role', cell: (u) => u.role },
    { header: 'Deleted by', cell: (u) => u.deleted_by_email || '-' },
  ],
  getId: (u) => u.id,
  load: () => adminService.getDeletedAccounts(),
  restore: (id) => adminService.restoreAccount(id),
  restoreBulk: (ids) => adminService.restoreAccountsBulk(ids),
  permanentDelete: (id) => adminService.permanentlyDeleteAccount(id),
  permanentDeleteBulk: (ids) => adminService.permanentlyDeleteAccountsBulk(ids),
  empty: () => adminService.emptyAccountsRecycleBin(),
};

const alertsRecycleConfig: RecycleBinConfig = {
  title: 'Alerts',
  emptyMessage: 'No deleted alerts.',
  columns: [
    { header: 'Deleted', cell: (a) => (a.deleted_at ? new Date(a.deleted_at).toLocaleString() : '-') },
    { header: 'Severity', cell: (a) => a.severity },
    { header: 'Reason', cell: (a) => a.reason },
    { header: 'Deleted by', cell: (a) => a.deleted_by_email || '-' },
  ],
  getId: (a) => a.id,
  load: () => adminService.getDeletedAlerts(),
  restore: (id) => adminService.restoreAlert(id),
  restoreBulk: (ids) => adminService.restoreAlertsBulk(ids),
  permanentDelete: (id) => adminService.permanentlyDeleteAlert(id),
  permanentDeleteBulk: (ids) => adminService.permanentlyDeleteAlertsBulk(ids),
  empty: () => adminService.emptyAlertsRecycleBin(),
};

const sourcesRecycleConfig: RecycleBinConfig = {
  title: 'Log sources',
  emptyMessage: 'No deleted log sources.',
  columns: [
    { header: 'Deleted', cell: (s) => (s.deleted_at ? new Date(s.deleted_at).toLocaleString() : '-') },
    { header: 'Name', cell: (s) => s.name },
    { header: 'Vendor', cell: (s) => s.vendor || '-' },
    { header: 'Deleted by', cell: (s) => s.deleted_by_email || '-' },
  ],
  getId: (s) => s.id,
  load: () => adminService.getDeletedSources(),
  restore: (id) => adminService.restoreSource(id),
  restoreBulk: (ids) => adminService.restoreSourcesBulk(ids),
  permanentDelete: (id) => adminService.permanentlyDeleteSource(id),
  permanentDeleteBulk: (ids) => adminService.permanentlyDeleteSourcesBulk(ids),
  empty: () => adminService.emptySourcesRecycleBin(),
};

function RecycleBinTab() {
  const [page, setPage] = useState(RECYCLE_PAGES[0]);
  const [summary, setSummary] = useState<Record<string, number> | null>(null);
  const [msg, setMsg] = useState<{ type: string; text: string } | null>(null);

  const loadSummary = useCallback(() => {
    adminService.getRecycleBinSummary().then(setSummary).catch(() => {});
  }, []);
  useEffect(() => { loadSummary(); }, [loadSummary]);

  const emptyEverything = async () => {
    if (!window.confirm('Empty the ENTIRE recycle bin? Every deleted log, account, alert and source will be permanently deleted. This cannot be undone.')) return;
    try {
      setMsg(null);
      const result = await adminService.emptyEntireRecycleBin();
      setMsg({ type: 'ok', text: `Permanently deleted: ${result.logs} log(s), ${result.accounts} account(s), ${result.alerts} alert(s), ${result.sources} source(s).` });
      loadSummary();
    } catch (e: any) {
      setMsg({ type: 'err', text: e.message });
    }
  };

  const badge: Record<string, string> = { Logs: 'logs', Accounts: 'accounts', Alerts: 'alerts', 'Log sources': 'sources' };

  return (
    <div className="pg-stack">
      <p className="pg-muted">
        Everything deleted anywhere in ULPF - logs, accounts, alerts and log sources - lands
        here first. Nothing is permanently gone until it's restored or emptied from below.
      </p>
      {msg && <div className={`pg-msg ${msg.type}`}>{msg.text}</div>}
      <div className="pg-row" style={{ justifyContent: 'space-between' }}>
        <div className="pg-tabs" style={{ marginBottom: 0, borderBottom: 'none' }}>
          {RECYCLE_PAGES.map((p) => (
            <button key={p} className={`pg-tab ${page === p ? 'active' : ''}`} onClick={() => setPage(p)}>
              {p}{summary ? ` (${summary[badge[p]] ?? 0})` : ''}
            </button>
          ))}
        </div>
        <ActionButton variant="danger" onClick={emptyEverything}>Empty entire recycle bin</ActionButton>
      </div>

      {page === 'Logs' && <RecycleBinPanel key="logs" config={logsRecycleConfig} />}
      {page === 'Accounts' && <RecycleBinPanel key="accounts" config={accountsRecycleConfig} />}
      {page === 'Alerts' && <RecycleBinPanel key="alerts" config={alertsRecycleConfig} />}
      {page === 'Log sources' && <RecycleBinPanel key="sources" config={sourcesRecycleConfig} />}
    </div>
  );
}

export default function Admin() {
  const [params, setParams] = useSearchParams();
  const urlTab = params.get('tab');
  const [tab, setTabState] = useState(urlTab && TABS.includes(urlTab) ? urlTab : TABS[0]);
  // Follow ?tab= changes (e.g. clicking a notification while already on Admin).
  useEffect(() => { if (urlTab && TABS.includes(urlTab)) setTabState(urlTab); }, [urlTab]);
  const setTab = (t: string) => { setTabState(t); setParams(t === TABS[0] ? {} : { tab: t }, { replace: true }); };
  return (
    <PageContainer>
      <div className="pg-title-row"><h1>Admin</h1></div>
      <div className="pg-tabs">
        {TABS.map((t) => <button key={t} className={`pg-tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>{t}</button>)}
      </div>
      {tab === 'Overview' && <Overview />}
      {tab === 'Users' && <Users />}
      {tab === 'Access requests' && <AccessRequests />}
      {tab === 'Logs' && <Logs embedded />}
      {tab === 'Alerts' && <Alerts />}
      {tab === 'Log sources' && <Sources />}
      {tab === 'Log access' && <LogAccess />}
      {tab === 'Recycle Bin' && <RecycleBinTab />}
      {tab === 'Audit log' && <Audit />}
      {tab === 'Reports' && <Reports />}
      {tab === 'Settings' && <AdminSettings />}
    </PageContainer>
  );
}
