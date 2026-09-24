import React from 'react';
import PageContainer from '../components/layout/PageContainer';
import { useAuth } from '../context/AuthContext';

export default function Settings() {
  const { user } = useAuth();
  return (
    <PageContainer>
      <div className="pg-stack">
        <div className="pg-title-row"><h1>Settings</h1></div>
        <div className="panel">
          <div className="panel-header"><h2>Your account</h2></div>
          <div className="panel-body">
            <dl className="pg-kv">
              <dt>Email</dt><dd>{user?.email}</dd>
              <dt>Role</dt><dd>{user?.role}</dd>
              <dt>Sensitive log access</dt>
              <dd>{user?.sensitiveAccess ? 'Approved: you can unlock original logs with the unlock password.' : 'Not approved: you only see the hidden version. Open a log and click Request access.'}</dd>
            </dl>
          </div>
        </div>
      </div>
    </PageContainer>
  );
}
