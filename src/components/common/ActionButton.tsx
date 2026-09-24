import React, { useState, useCallback } from 'react';
import { Loader2 } from 'lucide-react';

// A drop-in replacement for a plain <button className="pg-btn">. It visibly
// shows that a click registered (a pressed/active state) and, for anything
// that awaits a promise (an API call), shows a spinner + "Working..." label
// until it resolves - so nothing on screen ever looks like a dead click.
interface ActionButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  onClick?: (e: React.MouseEvent<HTMLButtonElement>) => any;
  variant?: 'primary' | 'ghost' | 'danger';
  size?: 'normal' | 'small';
  loadingText?: string;
  children: React.ReactNode;
}

export default function ActionButton({
  onClick,
  variant = 'primary',
  size = 'normal',
  loadingText = 'Working...',
  className = '',
  children,
  disabled,
  ...rest
}: ActionButtonProps) {
  const [busy, setBusy] = useState(false);
  const [justClicked, setJustClicked] = useState(false);

  const handleClick = useCallback(
    async (e: React.MouseEvent<HTMLButtonElement>) => {
      if (!onClick) return;
      setJustClicked(true);
      window.setTimeout(() => setJustClicked(false), 220);
      const result = onClick(e);
      if (result && typeof result.then === 'function') {
        setBusy(true);
        try {
          await result;
        } finally {
          setBusy(false);
        }
      }
    },
    [onClick]
  );

  const variantClass = variant === 'ghost' ? 'ghost' : variant === 'danger' ? 'danger' : '';
  const sizeClass = size === 'small' ? 'small' : '';

  return (
    <button
      type="button"
      className={`pg-btn ${variantClass} ${sizeClass} ${justClicked ? 'is-pressed' : ''} ${busy ? 'is-busy' : ''} ${className}`}
      onClick={handleClick}
      disabled={disabled || busy}
      {...rest}
    >
      {busy ? (
        <span className="pg-btn-spin">
          <Loader2 size={14} className="pg-spin-icon" />
          {loadingText}
        </span>
      ) : (
        children
      )}
    </button>
  );
}
