import React from 'react';
import { AlertCircle } from 'lucide-react';

interface ErrorMessageProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
}

export default function ErrorMessage({ title = 'Something went wrong', message, onRetry }: ErrorMessageProps) {
  return (
    <div className="error-container">
      <div className="error-icon">
        <AlertCircle size={48} />
      </div>
      <h2 className="error-title">{title}</h2>
      {message && <p className="error-message">{message}</p>}
      {onRetry && (
        <button className="btn-retry" onClick={onRetry}>
          Try Again
        </button>
      )}
    </div>
  );
}
