import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Trash2, CheckSquare, Square, ChevronRight, Loader2, Check, X } from 'lucide-react';
import PageContainer from '../components/layout/PageContainer';
import Loading from '../components/common/Loading';
import ActionButton from '../components/common/ActionButton';
import logService from '../services/logService';
import { useAuth } from '../context/AuthContext';

// Turns pasted/file text into a list of single log events.
function splitLogs(text: string, fmt: string): string[] {
  const t = text.trim();
  // A JSON object or a JSON array (array -> one event per item)
  if (t.startsWith('{') || t.startsWith('[')) {
    try {
      const parsed = JSON.parse(t);
      return Array.isArray(parsed) ? parsed.map((x) => JSON.stringify(x)) : [t];
    } catch {
      /* not one JSON document: maybe one JSON per line, handled below */
    }
  }
  const lines = t.split('\n').map((l) => l.trim()).filter(Boolean);
  // CSV: the first line is the header, so send it together with each row.
  const first = lines[0] || '';
  const looksLikeHeader = /timestamp|src_ip|source_ip|action|event_type/i.test(first) && first.includes(',');
  if ((fmt === 'csv' || looksLikeHeader) && lines.length > 1) {
    return lines.slice(1).map((row) => `${first}\n${row}`);
  }
  return lines;
}

const SOURCES = ['', 'syslog', 'cef', 'leef', 'json', 'csv'];

type QueueStatus = 'pending' | 'processing' | 'done' | 'error';
interface QueueItem {
  id: number;
  preview: string;
  status: QueueStatus;
  result?: any;
  error?: string;
}

type Scope = 'mine' | 'all';
type Msg = { type: string; text: string } | null;

// `embedded` = shown as a tab inside Admin (no page frame / title / recycle link).
export default function Logs({ embedded = false }: { embedded?: boolean }) {
  const { user, isAdmin, canUpload, refreshUser } = useAuth();
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [rawLog, setRawLog] = useState('');
  const [sourceType, setSourceType] = useState('');
  const [uploading, setUploading] = useState(false);
  const [notice, setNotice] = useState<{ type: string; text: string } | null>(null);
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [unlockPw, setUnlockPw] = useState('');
  const [unlocked, setUnlocked] = useState<any>(null);
  const [panelMsg, setPanelMsg] = useState<{ type: string; text: string } | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  // Analysts start on "My uploads"; admins and viewers start on "All logs".
  const [scope, setScope] = useState<Scope>(canUpload && !isAdmin ? 'mine' : 'all');
  const [uploadReq, setUploadReq] = useState<any>(null); // latest upload-access request (viewers)
  const [reqMsg, setReqMsg] = useState<Msg>(null);
  const detailsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (selected && detailsRef.current) {
      detailsRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [selected]);

  const load = useCallback(async (q = '', sc: Scope = scope) => {
    try {
      setLoading(true);
      setError('');
      const data = await logService.searchLogs(q, sc);
      setLogs(data);
      setChecked(new Set());
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { load('', scope); }, [load]); // eslint-disable-line react-hooks/exhaustive-deps

  const changeScope = (sc: Scope) => { setScope(sc); setSelected(null); load(query, sc); };

  // Viewers: look up whether they already asked for upload access.
  const loadUploadRequest = useCallback(async () => {
    try {
      const list: any[] = await logService.getMyAccessRequests();
      setUploadReq(list.find((r) => r.type === 'upload') || null);
    } catch { /* not critical */ }
  }, []);

  // On open, re-read the account: an admin may have approved this user since
  // they logged in, and the role is only re-fetched here.
  useEffect(() => {
    refreshUser().catch(() => {});
    loadUploadRequest();
  }, [refreshUser, loadUploadRequest]);

  const requestUpload = async () => {
    try {
      setReqMsg(null);
      await logService.requestUploadAccess();
      setReqMsg({ type: 'ok', text: 'Request sent. Wait for an admin to approve it.' });
      loadUploadRequest();
    } catch (e: any) {
      setReqMsg({ type: 'err', text: e.message });
    }
  };

  const checkApproval = async () => {
    try {
      setReqMsg(null);
      const u = await refreshUser();
      await loadUploadRequest();
      if (u.role === 'analyst' || u.role === 'admin') {
        setReqMsg({ type: 'ok', text: 'Approved! You can now upload logs.' });
        setScope('mine');
        load(query, 'mine');
      } else {
        setReqMsg({ type: 'ok', text: 'Not approved yet. Check again in a bit.' });
      }
    } catch (e: any) {
      setReqMsg({ type: 'err', text: e.message });
    }
  };

  // Uploads a pasted paragraph of many log lines ONE AT A TIME, updating a
  // visible queue as each one finishes - instead of silently processing
  // everything and only reporting a final count.
  const upload = async () => {
    if (!rawLog.trim()) return;
    const lines = splitLogs(rawLog, sourceType);
    const initialQueue: QueueItem[] = lines.map((line, i) => ({
      id: i,
      preview: line.length > 90 ? `${line.slice(0, 90)}...` : line,
      status: 'pending',
    }));
    setQueue(initialQueue);
    setNotice(null);
    setUploading(true);

    let ok = 0;
    let failed = 0;
    for (let i = 0; i < lines.length; i++) {
      setQueue((q) => q.map((item) => (item.id === i ? { ...item, status: 'processing' } : item)));
      try {
        // eslint-disable-next-line no-await-in-loop
        const result = await logService.uploadLog(lines[i], sourceType);
        ok++;
        setQueue((q) => q.map((item) => (item.id === i ? { ...item, status: 'done', result } : item)));
      } catch (e: any) {
        failed++;
        setQueue((q) => q.map((item) => (item.id === i ? { ...item, status: 'error', error: e.message } : item)));
      }
    }

    setUploading(false);
    setNotice({ type: failed ? 'err' : 'ok', text: `${ok} log(s) processed${failed ? `, ${failed} failed` : ''}.` });
    if (ok) { setRawLog(''); load(query, scope); }
  };

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = () => setRawLog(String(r.result || ''));
    r.readAsText(f);
  };

  const open = (log: any) => { setSelected(log); setUnlocked(null); setUnlockPw(''); setNotice(null); setPanelMsg(null); };

  const unlock = async () => {
    try {
      setPanelMsg(null);
      setUnlocked(await logService.unlockLog(selected.eventId, unlockPw));
      setPanelMsg({ type: 'ok', text: 'Unlocked. Original values are shown below.' });
    } catch (e: any) {
      setPanelMsg({ type: 'err', text: e.message });
    }
  };

  const requestAccess = async () => {
    try {
      await logService.requestSensitiveAccess();
      setPanelMsg({ type: 'ok', text: 'Request sent. An admin will review it.' });
    } catch (e: any) {
      setPanelMsg({ type: 'err', text: e.message });
    }
  };

  /* --- Select / delete / clear --- */
  // Only logs the caller may delete get a checkbox / delete button
  // (admin: every log, analyst: only their own uploads, viewer: none).
  const deletable = logs.filter((l) => l.canDelete);
  const allChecked = deletable.length > 0 && checked.size === deletable.length;
  const toggleAll = () => setChecked(allChecked ? new Set() : new Set(deletable.map((l) => l.eventId)));
  const toggleOne = (id: string) => setChecked((prev) => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  const deleteOne = async (id: string) => {
    try {
      await logService.deleteLog(id);
      setNotice({ type: 'ok', text: 'Log moved to the recycle bin.' });
      load(query, scope);
      if (selected?.eventId === id) setSelected(null);
    } catch (e: any) {
      setNotice({ type: 'err', text: e.message });
    }
  };

  const deleteSelected = async () => {
    if (checked.size === 0) return;
    if (!window.confirm(`Move ${checked.size} selected log(s) to the recycle bin?`)) return;
    try {
      const result = await logService.bulkDeleteLogs(Array.from(checked));
      setNotice({ type: 'ok', text: `${result.count} log(s) moved to the recycle bin.${result.skipped ? ` ${result.skipped} skipped (not yours).` : ''}` });
      load(query, scope);
    } catch (e: any) {
      setNotice({ type: 'err', text: e.message });
    }
  };

  const clearAll = async () => {
    if (deletable.length === 0) return;
    const text = isAdmin
      ? 'Clear ALL logs? Every log in the system will be moved to the recycle bin.'
      : 'Clear ALL your uploads? Every log you uploaded will be moved to the recycle bin.';
    if (!window.confirm(text)) return;
    try {
      const result = await logService.clearAllLogs();
      setNotice({ type: 'ok', text: `${result.count} log(s) moved to the recycle bin.` });
      load(query, scope);
    } catch (e: any) {
      setNotice({ type: 'err', text: e.message });
    }
  };

  const shown = unlocked || selected;
  const showUploader = isAdmin || canUpload;

  const content = (
      <div className="pg-stack">
        {!embedded && (
          <div className="pg-title-row">
            <h1>Logs</h1>
            {canUpload && (
              <ActionButton variant="ghost" size="small" onClick={() => navigate('/recycle-bin')}>
                <Trash2 size={14} /> Recycle bin <ChevronRight size={14} />
              </ActionButton>
            )}
          </div>
        )}

        {notice && <div className={`pg-msg ${notice.type}`}>{notice.text}</div>}

        {queue.length > 0 && (
          <div className="panel">
            <div className="panel-header"><h2>Processing {queue.length} log(s) one by one</h2></div>
            <div className="panel-body pg-stack">
              {queue.map((item) => (
                <div key={item.id} className={`upload-queue-item ${item.status}`}>
                  <span className="upload-queue-icon">
                    {item.status === 'pending' && <span className="pg-muted">#{item.id + 1}</span>}
                    {item.status === 'processing' && <Loader2 size={16} className="pg-spin-icon" />}
                    {item.status === 'done' && <Check size={16} color="var(--color-success)" />}
                    {item.status === 'error' && <X size={16} color="var(--color-danger)" />}
                  </span>
                  <span className="upload-queue-text">
                    {item.status === 'done' && item.result?.readableSummary ? item.result.readableSummary : item.preview}
                  </span>
                  {item.status === 'done' && (
                    <button className="pg-btn small ghost" onClick={() => open(item.result)}>Full details</button>
                  )}
                  {item.status === 'error' && <span className="pg-muted">{item.error}</span>}
                </div>
              ))}
            </div>
          </div>
        )}

        {!canUpload && (
          <div className="panel">
            <div className="panel-header"><h2>Upload logs</h2></div>
            <div className="panel-body pg-stack">
              <p className="pg-muted">
                Uploading logs is limited to analysts. You can view logs, but to upload you need an admin's approval.
              </p>
              {reqMsg && <div className={`pg-msg ${reqMsg.type}`}>{reqMsg.text}</div>}
              {uploadReq?.status === 'pending' ? (
                <div className="pg-row">
                  <span className="badge badge-warning">Waiting for admin approval</span>
                  <ActionButton variant="ghost" onClick={checkApproval}>Check status</ActionButton>
                </div>
              ) : (
                <div className="pg-row">
                  {uploadReq?.status === 'rejected' && <span className="badge badge-critical">Last request was rejected</span>}
                  <ActionButton onClick={requestUpload}>Request upload access</ActionButton>
                </div>
              )}
            </div>
          </div>
        )}

        {canUpload && (
        <div className="panel">
          <div className="panel-header"><h2>Upload logs</h2></div>
          <div className="panel-body">
            <textarea className="pg-textarea" placeholder="Paste one or more log lines here (syslog, CEF, LEEF, JSON, CSV)... each line is uploaded and shown one by one." value={rawLog} onChange={(e) => setRawLog(e.target.value)} />
            <div className="pg-row" style={{ marginTop: 10 }}>
              <input type="file" accept=".log,.txt,.json,.cef,.csv,.syslog" onChange={onFile} className="pg-muted" />
              <select className="pg-select" value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
                {SOURCES.map((s) => <option key={s} value={s}>{s || 'Auto-detect format'}</option>)}
              </select>
              <ActionButton onClick={upload} disabled={uploading || !rawLog.trim()} loadingText="Processing...">Upload</ActionButton>
            </div>
          </div>
        </div>
        )}

        <div className="panel">
          <div className="panel-header">
            <h2>{canUpload ? (scope === 'mine' ? 'My uploads' : 'All logs') : 'Logs'}</h2>
            <div className="pg-row">
              <input className="pg-input" placeholder="vendor, event, IP, action..." value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && load(query, scope)} />
              <ActionButton onClick={() => load(query, scope)}>Search</ActionButton>
            </div>
          </div>

          {canUpload && (
            <div className="pg-row" style={{ padding: '10px 20px', borderBottom: '1px solid var(--color-border)' }}>
              <button className={`pg-btn small ${scope === 'mine' ? '' : 'ghost'}`} onClick={() => changeScope('mine')}>My uploads</button>
              <button className={`pg-btn small ${scope === 'all' ? '' : 'ghost'}`} onClick={() => changeScope('all')}>All logs</button>
              {!isAdmin && scope === 'all' && <span className="pg-muted">You can only delete logs you uploaded.</span>}
            </div>
          )}

          {!loading && !error && deletable.length > 0 && (
            <div className="pg-row" style={{ padding: '10px 20px', borderBottom: '1px solid var(--color-border)' }}>
              <button className="pg-btn small ghost" onClick={toggleAll}>
                {allChecked ? <CheckSquare size={14} /> : <Square size={14} />}
                <span style={{ marginLeft: 6 }}>{allChecked ? 'Unselect all' : 'Select all'}</span>
              </button>
              <span className="pg-muted">{checked.size} of {deletable.length} selected</span>
              <ActionButton variant="danger" size="small" disabled={checked.size === 0} onClick={deleteSelected}>
                <Trash2 size={14} /> Delete selected
              </ActionButton>
              <ActionButton variant="danger" size="small" onClick={clearAll}>
                {isAdmin ? 'Clear all logs' : 'Clear all my uploads'}
              </ActionButton>
            </div>
          )}

          {loading ? <Loading message="Loading logs..." /> : error ? <div className="pg-empty">{error}</div> : logs.length === 0 ? (
            <div className="pg-empty">No logs found.</div>
          ) : (
            <div className="pg-table-wrap">
              <table className="pg-table">
                <thead><tr><th style={{ width: 32 }}></th><th>Time</th><th>Vendor</th><th>Summary</th><th>Source IP</th><th>Dest IP</th>{showUploader && <th>Uploaded by</th>}<th></th></tr></thead>
                <tbody>
                  {logs.map((l) => (
                    <tr key={l.eventId}>
                      <td>{l.canDelete && <input type="checkbox" checked={checked.has(l.eventId)} onChange={() => toggleOne(l.eventId)} />}</td>
                      <td>{l.timestamp ? new Date(l.timestamp).toLocaleString() : '-'}</td>
                      <td>{l.vendor}</td>
                      <td>{l.readableSummary || l.action || '-'}</td>
                      <td>{l.sourceIP || '-'}</td><td>{l.destIP || '-'}</td>
                      {showUploader && <td>{isAdmin ? (l.uploadedByEmail || '-') : (l.isMine ? 'You' : '-')}</td>}
                      <td>
                        <div className="pg-row" style={{ flexWrap: 'nowrap' }}>
                          <button className="pg-btn small ghost" onClick={() => open(l)}>Open</button>
                          {l.canDelete && <ActionButton size="small" variant="danger" onClick={() => deleteOne(l.eventId)}><Trash2 size={14} /></ActionButton>}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {selected && (
          <div className="panel" ref={detailsRef}>
            <div className="panel-header">
              <h2>Log details {unlocked ? '(unmasked)' : '(masked)'}</h2>
              <button className="pg-btn small ghost" onClick={() => setSelected(null)}>Close</button>
            </div>
            <div className="panel-body pg-stack">
              {panelMsg && <div className={`pg-msg ${panelMsg.type}`}>{panelMsg.text}</div>}
              {shown?.readableSummary && (
                <div className="pg-msg ok" style={{ fontSize: '0.95rem' }}>{shown.readableSummary}</div>
              )}
              <div className="pg-table-wrap">
                <table className="pg-table">
                  <thead>
                    <tr><th>Field</th><th>Masked (safe view)</th>{unlocked && <th>Original (unlocked)</th>}</tr>
                  </thead>
                  <tbody>
                    {Object.keys(unlocked || selected)
                      .filter((k) => !['rawLog', 'eventId', 'readableSummary', 'uploadedBy', 'uploadedByEmail', 'isMine', 'canDelete', 'deletedAt'].includes(k))
                      .map((k) => {
                        const m = String(selected[k] ?? '-');
                        const o = unlocked ? String(unlocked[k] ?? '-') : null;
                        return (
                          <tr key={k}>
                            <td>{k}</td>
                            <td>{m}</td>
                            {unlocked && <td style={o !== m ? { color: 'var(--color-success)', fontWeight: 600 } : undefined}>{o}</td>}
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>
              {unlocked?.rawLog && <div><div className="pg-muted">Original log line</div><pre className="pg-pre">{unlocked.rawLog}</pre></div>}
              {!unlocked && (user?.sensitiveAccess ? (
                <div className="pg-row">
                  <input className="pg-input" type="password" placeholder="Second password" value={unlockPw} onChange={(e) => setUnlockPw(e.target.value)} />
                  <ActionButton disabled={!unlockPw} onClick={unlock}>Unlock original</ActionButton>
                </div>
              ) : (
                <div className="pg-row">
                  <span className="pg-muted">You are not approved to see sensitive details.</span>
                  <ActionButton variant="ghost" onClick={requestAccess}>Request access</ActionButton>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
  );

  return embedded ? content : <PageContainer>{content}</PageContainer>;
}
