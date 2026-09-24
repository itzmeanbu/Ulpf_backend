import React from 'react';

export default function Loading({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="loading-container">
      <div className="spinner"></div>
      <span className="loading-text">{message}</span>
    </div>
  );
}
