import { useEffect, useState, type FormEvent } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ArrowRight, KeyRound, MailCheck, UserPlus } from 'lucide-react';
import { useAuth } from '../application/auth';
import { acceptInvitationSchema, recoveryCompleteSchema, recoveryRequestSchema } from '../domain/contracts';
import { AuthRequestError } from '../infrastructure/server-session-auth';
import { AuthLayout } from './App';

type Fields = Record<string, string>;
const issuesToFields = (issues: readonly { path: readonly PropertyKey[]; message: string }[]): Fields => Object.fromEntries(issues.map(issue => [String(issue.path[0] ?? 'form'), issue.message]));
const failure = (cause: unknown) => cause instanceof AuthRequestError ? cause.message : 'Something went wrong. Try again.';
const unavailable = 'Account services are not connected in this environment. Contact your workspace administrator.';

/** Reads the email-link token from the URL fragment (never sent to servers or logs) and strips it immediately. */
function useFragmentToken(): string | null {
  const location = useLocation(); const navigate = useNavigate();
  const [token] = useState(() => new URLSearchParams(location.hash.slice(1)).get('token_hash'));
  useEffect(() => { if (location.hash) navigate({ pathname: location.pathname, search: location.search }, { replace: true }); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return token;
}

function Field({ id, label, type = 'text', fields, ...rest }: { id: string; label: string; type?: string; fields: Fields; autoComplete?: string; inputMode?: 'numeric'; placeholder?: string; maxLength?: number }) {
  return <div className="form-field"><label htmlFor={id}>{label}</label><input id={id} name={id} type={type} aria-invalid={!!fields[id]} aria-describedby={fields[id] ? `${id}-error` : undefined} {...rest}/>{fields[id] && <p className="field-error" id={`${id}-error`}>{fields[id]}</p>}</div>;
}
function PasswordFields({ fields }: { fields: Fields }) {
  return <><Field id="password" label="New password" type="password" autoComplete="new-password" placeholder="At least 12 characters" fields={fields}/><Field id="confirm" label="Confirm new password" type="password" autoComplete="new-password" placeholder="Repeat your new password" fields={fields}/></>;
}
function readPassword(data: FormData): { password: string } | { fields: Fields } {
  const password = String(data.get('password') ?? '');
  return password === String(data.get('confirm') ?? '') ? { password } : { fields: { confirm: 'Passwords do not match.' } };
}
function Header({ icon, eyebrow, title, text }: { icon: React.ReactNode; eyebrow: string; title: string; text: string }) {
  return <><div className="welcome-icon">{icon}</div><span className="eyebrow muted">{eyebrow}</span><h2>{title}</h2><p className="login-description">{text}</p></>;
}

export function ForgotPassword() {
  const { access } = useAuth();
  const [step, setStep] = useState<'request' | 'verify'>('request');
  const [email, setEmail] = useState(''); const [notice, setNotice] = useState(''); const [error, setError] = useState(''); const [fields, setFields] = useState<Fields>({}); const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  async function request(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError('');
    const parsed = recoveryRequestSchema.safeParse({ email: new FormData(event.currentTarget).get('email') });
    if (!parsed.success) return setFields(issuesToFields(parsed.error.issues));
    if (!access) return setError(unavailable);
    setFields({}); setBusy(true);
    try { setNotice(await access.requestRecovery(parsed.data.email)); setEmail(parsed.data.email); setStep('verify'); } catch (cause) { setError(failure(cause)); } finally { setBusy(false); }
  }
  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError('');
    const data = new FormData(event.currentTarget); const pw = readPassword(data);
    if ('fields' in pw) return setFields(pw.fields);
    const parsed = recoveryCompleteSchema.safeParse({ email, code: String(data.get('code') ?? '').trim(), password: pw.password });
    if (!parsed.success) return setFields(issuesToFields(parsed.error.issues));
    if (!access) return setError(unavailable);
    setFields({}); setBusy(true);
    try { await access.completeRecovery(parsed.data); navigate('/login?notice=password-set', { replace: true }); } catch (cause) { if (cause instanceof AuthRequestError) setFields(cause.fields); setError(failure(cause)); } finally { setBusy(false); }
  }
  return <AuthLayout>
    <Header icon={<KeyRound size={24}/>} eyebrow="PASSWORD RECOVERY" title={step === 'request' ? 'Reset your password.' : 'Check your email.'} text={step === 'request' ? 'Enter your work email. If it belongs to an active workspace member, we email a 6-digit code.' : notice}/>
    {step === 'request'
      ? <form noValidate onSubmit={request}><Field id="email" label="Work email" type="email" autoComplete="username" placeholder="you@company.com" fields={fields}/>{error && <p className="form-error" role="alert">{error}</p>}<button className="primary-button" disabled={busy} type="submit">{busy ? 'Sending…' : 'Send reset code'}<ArrowRight size={18}/></button></form>
      : <form noValidate onSubmit={verify}><Field id="code" label="6-digit code" inputMode="numeric" autoComplete="one-time-code" placeholder="123456" maxLength={6} fields={fields}/><PasswordFields fields={fields}/>{error && <p className="form-error" role="alert">{error}</p>}<button className="primary-button" disabled={busy} type="submit">{busy ? 'Updating…' : 'Set new password'}<ArrowRight size={18}/></button><button type="button" className="text-button spaced" onClick={() => { setStep('request'); setError(''); setFields({}); }}>Use a different email or request a new code</button></form>}
    <div className="access-note"><MailCheck size={16}/><p>Codes expire quickly and can be tried only a few times.<br/><span><Link to="/login">Back to sign in</Link></span></p></div>
  </AuthLayout>;
}

function TokenPasswordPage({ kind }: { kind: 'invite' | 'recovery' }) {
  const { access } = useAuth(); const navigate = useNavigate(); const tokenHash = useFragmentToken();
  const [error, setError] = useState(''); const [fields, setFields] = useState<Fields>({}); const [busy, setBusy] = useState(false);
  const invite = kind === 'invite';
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError('');
    const pw = readPassword(new FormData(event.currentTarget));
    if ('fields' in pw) return setFields(pw.fields);
    const input = { tokenHash: tokenHash ?? '', password: pw.password };
    const parsed = invite ? acceptInvitationSchema.safeParse(input) : recoveryCompleteSchema.safeParse(input);
    if (!parsed.success) { const f = issuesToFields(parsed.error.issues); setFields(f); if (f.tokenHash || f.form) setError(f.tokenHash ?? f.form ?? ''); return; }
    if (!access) return setError(unavailable);
    setFields({}); setBusy(true);
    try { await (invite ? access.acceptInvitation(input) : access.completeRecovery(input)); navigate('/login?notice=password-set', { replace: true }); }
    catch (cause) { if (cause instanceof AuthRequestError) setFields(cause.fields); setError(failure(cause)); } finally { setBusy(false); }
  }
  return <AuthLayout>
    <Header icon={invite ? <UserPlus size={24}/> : <KeyRound size={24}/>} eyebrow={invite ? 'WORKSPACE INVITATION' : 'PASSWORD RECOVERY'} title={invite ? 'Create your password.' : 'Choose a new password.'} text={invite ? 'You were invited to the ThriveSource workspace. Create a password only you know.' : 'Set a new password for your Hourvia account. Other signed-in sessions are ended.'}/>
    {!tokenHash ? <p className="form-error" role="alert">{invite ? 'This invitation link is incomplete. Open it again from your email, or ask your workspace admin for a new invitation.' : 'This reset link is incomplete. Open it again from your email or request a new code.'}</p>
      : <form noValidate onSubmit={submit}><PasswordFields fields={fields}/>{error && <p className="form-error" role="alert">{error}</p>}<button className="primary-button" disabled={busy} type="submit">{busy ? 'Saving…' : invite ? 'Create password' : 'Set new password'}<ArrowRight size={18}/></button></form>}
    <div className="access-note"><KeyRound size={16}/><p>Use at least 12 characters.<br/><span><Link to={invite ? '/login' : '/forgot-password'}>{invite ? 'Back to sign in' : 'Request a new code'}</Link></span></p></div>
  </AuthLayout>;
}
export const AcceptInvitation = () => <TokenPasswordPage kind="invite"/>;
export const ResetPasswordLink = () => <TokenPasswordPage kind="recovery"/>;
