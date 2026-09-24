import React from 'react';
import PageContainer from '../components/layout/PageContainer';
import RecycleBinPanel, { RecycleBinConfig } from '../components/common/RecycleBinPanel';
import logService from '../services/logService';

// Standalone Recycle Bin page for deleted Logs, reachable from the sidebar.
// (Accounts / Alerts / Log Sources have their own recycle bin pages inside
// Admin > Recycle Bin, since only an admin manages those.)
const logsConfig: RecycleBinConfig = {
  title: 'Logs',
  emptyMessage: 'The recycle bin is empty. Deleted logs will show up here.',
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

export default function RecycleBin() {
  return (
    <PageContainer>
      <div className="pg-title-row"><h1>Recycle Bin</h1></div>
      <p className="pg-muted" style={{ marginBottom: 16 }}>
        Deleted logs land here first. Restore them or delete them forever - nothing is
        permanently gone until you empty the bin.
      </p>
      <RecycleBinPanel config={logsConfig} />
    </PageContainer>
  );
}
