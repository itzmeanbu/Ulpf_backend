import React, { useState, useEffect } from 'react';
import Loading from '../components/common/Loading';
import ActionButton from '../components/common/ActionButton';
import adminService from '../services/adminService';

interface Field {
  key: string;
  type: 'bool' | 'select' | 'num';
  label: string;
  help?: string;
  options?: string[];
}

// One settings box: a list of options, each with a short plain explanation.
function Options({ title, intro, fields, load, save }: { title: string; intro?: string; fields: Field[]; load: () => Promise<any>; save: (cfg: any) => Promise<any> }) {
  const [cfg, setCfg] = useState<any>(null);
  const [msg, setMsg] = useState<{ type: string; text: string } | null>(null);
  useEffect(() => {
    load().then(setCfg).catch((e: any) => setMsg({ type: 'err', text: e.message }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);

  const submit = async () => {
    try { setMsg(null); await save(cfg); setMsg({ type: 'ok', text: 'Saved.' }); }
    catch (e: any) { setMsg({ type: 'err', text: e.message }); }
  };

  return (
    <div className="panel">
      <div className="panel-header"><h2>{title}</h2></div>
      <div className="panel-body">
        {intro && <p className="pg-muted" style={{ marginBottom: 12 }}>{intro}</p>}
        {!cfg ? (msg ? null : <Loading />) : (
          <>
            {fields.map((f) => (
              <div key={f.key} style={{ marginBottom: 14 }}>
                {f.type === 'bool' ? (
                  <label className="pg-toggle" style={{ paddingBottom: 2 }}>
                    <input type="checkbox" checked={!!cfg[f.key]} onChange={(e) => setCfg({ ...cfg, [f.key]: e.target.checked })} />
                    <strong>{f.label}</strong>
                  </label>
                ) : f.type === 'select' ? (
                  <label className="pg-field" style={{ marginBottom: 2 }}><strong>{f.label}</strong>
                    <select className="pg-select" value={cfg[f.key]} onChange={(e) => setCfg({ ...cfg, [f.key]: e.target.value })}>
                      {(f.options || []).map((o) => <option key={o}>{o}</option>)}
                    </select>
                  </label>
                ) : (
                  <label className="pg-field" style={{ marginBottom: 2 }}><strong>{f.label}</strong>
                    <input className="pg-input" type="number" min="1" value={cfg[f.key]} onChange={(e) => setCfg({ ...cfg, [f.key]: Number(e.target.value) })} />
                  </label>
                )}
                <div className="pg-muted" style={{ marginLeft: f.type === 'bool' ? 28 : 0 }}>{f.help}</div>
              </div>
            ))}
            <ActionButton onClick={submit}>Save</ActionButton>
          </>
        )}
        {msg && <div className={`pg-msg ${msg.type}`} style={{ marginTop: 10 }}>{msg.text}</div>}
      </div>
    </div>
  );
}

function UnlockPassword() {
  const [pw, setPw] = useState('');
  const [msg, setMsg] = useState<{ type: string; text: string } | null>(null);
  const submit = async () => {
    try { setMsg(null); await adminService.setSecondaryPassword(pw); setPw(''); setMsg({ type: 'ok', text: 'Unlock password updated.' }); }
    catch (e: any) { setMsg({ type: 'err', text: e.message }); }
  };
  return (
    <div className="panel">
      <div className="panel-header"><h2>Unlock password</h2></div>
      <div className="panel-body">
        <p className="pg-muted" style={{ marginBottom: 12 }}>
          Users you approve for sensitive access type this password to see the original, unhidden log.
          Share it only with them. Changing it here replaces the old one straight away (at least 8 characters).
        </p>
        <div className="pg-row">
          <input className="pg-input" type="password" placeholder="New unlock password" value={pw} onChange={(e) => setPw(e.target.value)} />
          <ActionButton disabled={pw.length < 8} onClick={submit}>Update</ActionButton>
        </div>
        {msg && <div className={`pg-msg ${msg.type}`} style={{ marginTop: 10 }}>{msg.text}</div>}
      </div>
    </div>
  );
}

const STATUS_HELP: Record<string, string> = {
  aesEncryption: 'Every log is stored encrypted.',
  masking: 'Sensitive data is hidden in the normal view.',
  https: 'The connection to the server is secure.',
  rateLimiting: 'Too many requests from one place get blocked.',
  loginProtection: 'Passwords are protected and repeated failed logins are watched.',
};

function SecurityStatus() {
  const [status, setStatus] = useState<Record<string, boolean> | null>(null);
  useEffect(() => { adminService.getSecurityStatus().then(setStatus).catch(() => {}); }, []);
  if (!status) return null;
  return (
    <div className="panel">
      <div className="panel-header"><h2>Security status</h2></div>
      <div className="panel-body">
        <p className="pg-muted" style={{ marginBottom: 12 }}>A quick check that the protections are running. All should say ON.</p>
        {Object.entries(status).map(([k, v]) => (
          <div key={k} style={{ marginBottom: 8 }}>
            <span className={`badge ${v ? 'badge-success' : 'badge-critical'}`}>{k}: {v ? 'on' : 'off'}</span>
            <span className="pg-muted" style={{ marginLeft: 10 }}>{STATUS_HELP[k]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function AdminSettings() {
  return (
    <div className="pg-stack">
      <Options
        title="Masking rules"
        intro="Choose what is hidden when normal users look at logs. Turn an option off to show that kind of data. Applies immediately, also to old logs."
        load={adminService.getMasking} save={adminService.saveMasking}
        fields={[
          { key: 'email', type: 'bool', label: 'Hide email addresses', help: 'bob@company.com is shown as b****@****.com' },
          { key: 'password', type: 'bool', label: 'Hide passwords', help: 'Anything written like pass=... or pwd=... is replaced with REDACTED.' },
          { key: 'apiKey', type: 'bool', label: 'Hide keys and tokens', help: 'Anything written like key=... or token=... is replaced with REDACTED.' },
          { key: 'phone', type: 'bool', label: 'Hide phone numbers', help: 'Only the first two digits stay visible.' },
          { key: 'ip', type: 'bool', label: 'Hide IP addresses', help: '203.0.113.9 is shown as 203.0.xxx.xxx' },
        ]}
      />
      <Options
        title="Detection settings"
        intro="Controls when the site creates alerts by itself."
        load={adminService.getAiSettings} save={adminService.saveAiSettings}
        fields={[
          { key: 'anomalyDetection', type: 'bool', label: 'Watch failed logins', help: 'Alert when the same email fails to log in too many times within 5 minutes. Medium: 5 failures.' },
          { key: 'threatCorrelation', type: 'bool', label: 'Watch repeated IPs', help: 'Alert when the same IP appears in too many logs within 10 minutes. Medium: 4 logs.' },
          { key: 'automaticAlerts', type: 'bool', label: 'Create alerts automatically', help: 'Main switch. If off, NO alerts are created at all, even if the two watches above are on.' },
          { key: 'aiMasking', type: 'bool', label: 'AI masking (not working yet)', help: 'Does nothing for now. Hiding data uses fixed rules, not AI.' },
          { key: 'sensitivity', type: 'select', label: 'Sensitivity', options: ['low', 'medium', 'high'], help: 'Failed logins needed: low 8, medium 5, high 3. Logs from the same IP needed: low 6, medium 4, high 3. High gives more alerts sooner; low gives fewer.' },
        ]}
      />
      <Options
        title="System settings"
        load={adminService.getSystemSettings} save={adminService.saveSystemSettings}
        fields={[
          { key: 'sessionTimeoutMinutes', type: 'num', label: 'Login lasts (minutes)', help: '480 minutes = 8 hours. After this time the user must sign in again. Applies to new logins.' },
          { key: 'logRetentionDays', type: 'num', label: 'Keep logs (days)', help: 'Saved, but old logs are not deleted automatically yet.' },
          { key: 'maxUploadSizeMb', type: 'num', label: 'Max upload size (MB)', help: 'Saved only. The real limit is 2 MB and is fixed in the server code.' },
          { key: 'notifyOnCriticalAlerts', type: 'bool', label: 'Notify on critical alerts', help: 'Saved, but the site cannot send notifications yet.' },
        ]}
      />
      <UnlockPassword />
      <SecurityStatus />
    </div>
  );
}
