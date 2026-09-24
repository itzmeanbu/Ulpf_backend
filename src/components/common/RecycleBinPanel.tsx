import React, { useState, useEffect, useCallback } from 'react';
import { RotateCcw, Trash2, CheckSquare, Square } from 'lucide-react';
import Loading from './Loading';
import ActionButton from './ActionButton';

export interface RecycleColumn {
  header: string;
  cell: (item: any) => React.ReactNode;
}

export interface RecycleBinConfig {
  title: string;
  emptyMessage: string;
  columns: RecycleColumn[];
  getId: (item: any) => string;
  load: () => Promise<any[]>;
  restore: (id: string) => Promise<any>;
  restoreBulk: (ids: string[]) => Promise<any>;
  permanentDelete: (id: string) => Promise<any>;
  permanentDeleteBulk: (ids: string[]) => Promise<any>;
  empty: () => Promise<any>;
}

// One "page" of the Recycle Bin. Reused for Logs, Accounts, Alerts and Log
// Sources - every category gets select-all, restore, permanently-delete-
// forever and an Empty-this-bin button that behave the same way.
export default function RecycleBinPanel({ config }: { config: RecycleBinConfig }) {
  const [items, setItems] = useState<any[] | null>(null);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [msg, setMsg] = useState<{ type: string; text: string } | null>(null);

  const load = useCallback(async () => {
    try {
      setError('');
      const data = await config.load();
      setItems(data);
      setSelected(new Set());
    } catch (e: any) {
      setError(e.message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config]);

  useEffect(() => { setItems(null); load(); }, [load]);

  const allSelected = !!items && items.length > 0 && selected.size === items.length;

  const toggleAll = () => {
    if (!items) return;
    setSelected(allSelected ? new Set() : new Set(items.map(config.getId)));
  };

  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const run = async (action: () => Promise<any>, okText: string) => {
    try {
      setMsg(null);
      await action();
      setMsg({ type: 'ok', text: okText });
      await load();
    } catch (e: any) {
      setMsg({ type: 'err', text: e.message });
    }
  };

  if (error) return <div className="pg-msg err">{error}</div>;
  if (!items) return <Loading message={`Loading ${config.title.toLowerCase()}...`} />;

  return (
    <div className="pg-stack">
      {msg && <div className={`pg-msg ${msg.type}`}>{msg.text}</div>}

      <div className="pg-row" style={{ justifyContent: 'space-between' }}>
        <div className="pg-row">
          <button className="pg-btn small ghost" onClick={toggleAll} disabled={items.length === 0}>
            {allSelected ? <CheckSquare size={14} /> : <Square size={14} />}
            <span style={{ marginLeft: 6 }}>{allSelected ? 'Unselect all' : 'Select all'}</span>
          </button>
          <span className="pg-muted">{selected.size} of {items.length} selected</span>
        </div>
        <div className="pg-row">
          <ActionButton
            variant="ghost"
            size="small"
            disabled={selected.size === 0}
            onClick={() => run(() => config.restoreBulk(Array.from(selected)), 'Restored.')}
          >
            <RotateCcw size={14} /> Restore selected
          </ActionButton>
          <ActionButton
            variant="danger"
            size="small"
            disabled={selected.size === 0}
            onClick={() =>
              window.confirm(`Permanently delete ${selected.size} item(s)? This cannot be undone.`) &&
              run(() => config.permanentDeleteBulk(Array.from(selected)), 'Permanently deleted.')
            }
          >
            <Trash2 size={14} /> Delete selected forever
          </ActionButton>
          <ActionButton
            variant="danger"
            size="small"
            disabled={items.length === 0}
            onClick={() =>
              window.confirm(`Empty the ${config.title} recycle bin? All ${items.length} item(s) will be permanently deleted.`) &&
              run(() => config.empty(), 'Recycle bin emptied.')
            }
          >
            Empty recycle bin
          </ActionButton>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="pg-empty">{config.emptyMessage}</div>
      ) : (
        <div className="panel pg-table-wrap">
          <table className="pg-table">
            <thead>
              <tr>
                <th style={{ width: 32 }}></th>
                {config.columns.map((c) => <th key={c.header}>{c.header}</th>)}
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const id = config.getId(item);
                return (
                  <tr key={id}>
                    <td>
                      <input type="checkbox" checked={selected.has(id)} onChange={() => toggleOne(id)} />
                    </td>
                    {config.columns.map((c) => <td key={c.header}>{c.cell(item)}</td>)}
                    <td>
                      <div className="pg-row" style={{ flexWrap: 'nowrap' }}>
                        <ActionButton variant="ghost" size="small" onClick={() => run(() => config.restore(id), 'Restored.')}>
                          <RotateCcw size={14} />
                        </ActionButton>
                        <ActionButton
                          variant="danger"
                          size="small"
                          onClick={() =>
                            window.confirm('Permanently delete this item? This cannot be undone.') &&
                            run(() => config.permanentDelete(id), 'Permanently deleted.')
                          }
                        >
                          <Trash2 size={14} />
                        </ActionButton>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
