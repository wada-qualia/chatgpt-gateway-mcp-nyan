import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';

function cx(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ');
}

export type ButtonVariant = 'default' | 'primary' | 'solid' | 'danger';

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
};

export function Button({ className, variant = 'default', ...props }: ButtonProps) {
  return <button className={cx(variant === 'primary' && 'primary-action', variant === 'solid' && 'solid', variant === 'danger' && 'danger', className)} {...props} />;
}

export type IconButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  'aria-label': string;
};

export function IconButton({ className, ...props }: IconButtonProps) {
  return <Button className={cx('icon-button', className)} {...props} />;
}

export function StatusPill({ status }: { status: string }) {
  return (
    <span className={`status-pill ${statusClass(status)}`}>
      <span className="dot" />
      {status}
    </span>
  );
}

export type SearchFieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange'> & {
  icon?: ReactNode;
  onChange: (value: string) => void;
  value: string;
};

export function SearchField({ icon, onChange, value, ...props }: SearchFieldProps) {
  return (
    <label className="search-field">
      <input value={value} onChange={(event) => onChange(event.target.value)} {...props} />
      {icon}
    </label>
  );
}

export function SegmentedControl<TValue extends string>({
  options,
  value,
  onChange
}: {
  options: Array<{ label: string; value: TValue }>;
  value: TValue;
  onChange: (value: TValue) => void;
}) {
  return (
    <div className="segmented">
      {options.map((option) => (
        <Button key={option.value} className={value === option.value ? 'active' : ''} onClick={() => onChange(option.value)} type="button">
          {option.label}
        </Button>
      ))}
    </div>
  );
}

export function TableFrame({ children, compact = false }: { children: ReactNode; compact?: boolean }) {
  return <div className={cx('table-frame', compact && 'compact')}>{children}</div>;
}

export function ResourceCard({ children }: { children: ReactNode }) {
  return <article className="resource-card">{children}</article>;
}

export function CommandBox({ children }: { children: ReactNode }) {
  return <pre className="command-box">{children}</pre>;
}

function statusClass(status: string) {
  if (status === 'online' || status === 'running' || status === 'active' || status === 'success') return 'good';
  if (status === 'pending') return 'warn';
  return 'bad';
}
