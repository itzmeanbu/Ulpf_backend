import React from 'react';

export default function PageContainer({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <div className="page-container">
      {title && <h1 className="dashboard-title">{title}</h1>}
      {children}
    </div>
  );
}
