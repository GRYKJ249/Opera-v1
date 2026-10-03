import { t } from '../core/i18n.js';

/** Google وGitHub والبصمة (WebAuthn). الجلسة كوكي HttpOnly يضعه الخادم، والصفحة لا ترى أي سر. */
const MSG: Record<string, string> = {
  not_configured: 'الدخول عبر هذا المزوّد لم يُفعَّل على الخادم بعد. استخدم البريد وكلمة المرور.',
  not_owner: 'حساب المزوّد هذا غير مرتبط بحساب في الموقع.',
  unverified_email: 'بريد هذا الحساب غير مؤكَّد لدى المزوّد.',
  bad_state: 'انتهت صلاحية المحاولة. أعد المحاولة.',
  provider_error: 'تعذّر الاتصال بالمزوّد. أعد المحاولة.',
  denied: 'أُلغي تسجيل الدخول.',
  blocked: 'محاولات كثيرة. حاول لاحقاً.',
  locked: 'الحساب مقفل مؤقتاً. حاول لاحقاً.',
  invalid: 'تعذّر تسجيل الدخول.',
  expired: 'انتهت صلاحية المحاولة. أعد المحاولة.',
  no_passkey: 'لا توجد بصمة مسجّلة. سجّل الدخول بالبريد ثم اضغط «إضافة بصمة لهذا الجهاز».',
  unsupported: 'هذا المتصفح لا يدعم البصمة، أو الصفحة ليست على https.',
  cancelled: 'أُلغيت العملية.',
  network: 'تعذّر الاتصال بالخادم. تأكد أنه يعمل ثم أعد المحاولة.',
};
const b64d = (s: string): ArrayBuffer => { const p = s.replace(/-/g, '+').replace(/_/g, '/'); return Uint8Array.from(atob(p + '='.repeat((4 - p.length % 4) % 4)), c => c.charCodeAt(0)).buffer; };
const b64e = (b: ArrayBuffer): string => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function post(url: string, body: unknown = {}): Promise<{ ok: boolean; j: any }> {
  try {
    const r = await fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { ok: r.ok, j: await r.json().catch(() => null) };
  } catch { return { ok: false, j: { error: 'network' } }; }
}

export function initSocial(): void {
  const btns = document.querySelectorAll<HTMLButtonElement>('.lgs .btn[data-p]');
  const msg = document.getElementById('lgm'); if (!btns.length || !msg) return;
  const say = (k: string, err = true) => { msg.classList.toggle('err', err); msg.textContent = t(MSG[k] ?? MSG.invalid); };
  const busy = (b: HTMLButtonElement, on: boolean) => { b.disabled = on; b.classList.toggle('ld', on); };
  const home = () => { location.href = new URL('../index.html', location.href).href; };

  // رجوع من Google/GitHub برمز خطأ في الرابط
  const oe = new URLSearchParams(location.search).get('oauth');
  if (oe) say(oe);

  const oauth = async (p: string, b: HTMLButtonElement) => {
    busy(b, true);
    try {
      const j = await fetch('/api/auth/providers', { credentials: 'same-origin' }).then(r => r.json());
      if (!j[p]) { say('not_configured'); busy(b, false); return; }
      location.href = `/api/auth/oauth/${p}`; // الخادم يحوّل إلى المزوّد ثم يعيدك مسجَّلاً
    } catch { say('network'); busy(b, false); }
  };

  const passkeyLogin = async (b: HTMLButtonElement) => {
    if (!window.PublicKeyCredential || !navigator.credentials) return say('unsupported');
    busy(b, true); msg.textContent = '';
    try {
      const o = await post('/api/auth/passkey/login/options');
      if (!o.ok) return say(o.j?.error ?? 'network');
      const opt = o.j;
      const cred = await navigator.credentials.get({ publicKey: {
        challenge: b64d(opt.challenge), rpId: opt.rpId, timeout: opt.timeout, userVerification: 'required',
        allowCredentials: (opt.allowCredentials ?? []).map((c: any) => ({ type: 'public-key' as const, id: b64d(c.id) })),
      } }) as PublicKeyCredential | null;
      if (!cred) return say('cancelled');
      const a = cred.response as AuthenticatorAssertionResponse;
      const v = await post('/api/auth/passkey/login/verify', { id: cred.id, response: { clientDataJSON: b64e(a.clientDataJSON), authenticatorData: b64e(a.authenticatorData), signature: b64e(a.signature) } });
      if (!v.ok) return say(v.j?.error ?? 'invalid');
      say('', false); msg.textContent = t('تم تسجيل الدخول.'); setTimeout(home, 400);
    } catch (e) { say((e as DOMException).name === 'NotAllowedError' ? 'cancelled' : 'unsupported'); }
    finally { busy(b, false); }
  };

  btns.forEach(b => b.addEventListener('click', () => b.dataset.p === 'fp' ? passkeyLogin(b) : oauth(b.dataset.p ?? '', b)));

  // مستخدم مسجَّل الدخول: إضافة بصمة لهذا الجهاز + تسجيل الخروج (تظهر في صفحة الدخول فقط)
  const acct = document.getElementById('lgacct'), add = document.getElementById('lgpk') as HTMLButtonElement | null, out = document.getElementById('lgout') as HTMLButtonElement | null;
  if (!acct || !add || !out) return;
  fetch('/api/auth/me', { credentials: 'same-origin' }).then(r => r.ok ? r.json() : null).then(j => { if (j?.user) acct.hidden = false; }).catch(() => { /* لا يوجد خادم */ });
  out.onclick = async () => { await post('/api/auth/logout'); location.href = '/'; };
  add.onclick = async () => {
    if (!window.PublicKeyCredential || !navigator.credentials) return say('unsupported');
    busy(add, true); msg.textContent = '';
    try {
      const o = await post('/api/auth/passkey/register/options');
      if (!o.ok) return say(o.j?.error ?? 'network');
      const opt = o.j;
      const cred = await navigator.credentials.create({ publicKey: {
        challenge: b64d(opt.challenge), rp: opt.rp, timeout: opt.timeout, attestation: 'none',
        user: { id: b64d(opt.user.id), name: opt.user.name, displayName: opt.user.displayName },
        pubKeyCredParams: opt.pubKeyCredParams, authenticatorSelection: opt.authenticatorSelection,
        excludeCredentials: (opt.excludeCredentials ?? []).map((c: any) => ({ type: 'public-key' as const, id: b64d(c.id) })),
      } }) as PublicKeyCredential | null;
      if (!cred) return say('cancelled');
      const a = cred.response as AuthenticatorAttestationResponse;
      const v = await post('/api/auth/passkey/register/verify', { id: cred.id, transports: a.getTransports?.() ?? [], response: { clientDataJSON: b64e(a.clientDataJSON), attestationObject: b64e(a.attestationObject) } });
      if (!v.ok) return say(v.j?.error ?? 'invalid');
      say('', false); msg.textContent = t('تمت إضافة البصمة لهذا الجهاز. يمكنك الآن الدخول بها.');
    } catch (e) { say((e as DOMException).name === 'NotAllowedError' ? 'cancelled' : (e as DOMException).name === 'InvalidStateError' ? 'invalid' : 'unsupported'); }
    finally { busy(add, false); }
  };
}
