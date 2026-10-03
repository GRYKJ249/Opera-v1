import { $, RM, ls } from '../core/utils.js';
import { t } from '../core/i18n.js';

const LG_DOMAINS = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com'];
const LG_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const LG_KEY = 'op-email';
const ROOT_HOME = '../index.html';
const ERR: Record<string, string> = {
  pending: 'حسابك لم يُفعَّل بعد. أدخل رمز التأكيد المرسل إلى بريدك.',
  invalid: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.',
  locked: 'الحساب مقفل مؤقتاً بسبب محاولات كثيرة. حاول بعد 15 دقيقة.',
  blocked: 'محاولات كثيرة من هذا الجهاز. حاول لاحقاً.',
  network: 'تعذّر الاتصال بالخادم. تأكد أنه يعمل ثم أعد المحاولة.',
};
type LoginReply = { ok: true; restored: boolean } | { ok: false; error: string };

/** يرسل بيانات الدخول إلى الخادم. الجلسة تُحفظ في كوكي HttpOnly فلا يصلها كود الصفحة. */
async function sendLogin(email: string, password: string, remember: boolean): Promise<LoginReply> {
  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, remember }),
    });
    const j = await r.json().catch(() => null);
    if (r.ok && j?.user) return { ok: true, restored: !!j.restored };
    return { ok: false, error: j?.error ?? 'network' };
  } catch { return { ok: false, error: 'network' }; }
}

/** نموذج الدخول: تحقق الواجهة في المتصفح، والتحقق الحقيقي على الخادم (/api/auth/login) */
export function initLogin(): void {
  const form = document.getElementById('lgf') as HTMLFormElement | null;
  if (!form) return;
  const em = $('lge') as HTMLInputElement, pw = $('lgp') as HTMLInputElement;
  const msg = $('lgm'), hint = $('lgeh'), caps = $('lgcl'), sug = $('lgsg');
  const clr = $('lgclr') as HTMLButtonElement, eye = $('lgeye') as HTMLButtonElement, rem = $('lgr') as HTMLInputElement;
  const go = form.querySelector('button[type=submit]') as HTMLButtonElement;
  const sub = document.querySelector('.lgc .sub') as HTMLElement | null;
  let touched = false, busy = false;

  const valid = () => LG_EMAIL.test(em.value.trim());

  // 1) تحقق مباشر من صيغة البريد مع زر مسح الحقل
  const paintEmail = () => {
    const v = em.value.trim();
    clr.hidden = !v;
    const bad = touched && !!v && !valid(), good = !!v && valid();
    em.classList.toggle('bad', bad); em.classList.toggle('good', good);
    em.setAttribute('aria-invalid', String(bad));
    hint.textContent = bad ? t('صيغة البريد الإلكتروني غير صحيحة.') : '';
  };

  // 2) اقتراح نطاقات البريد الشائعة بعد كتابة @
  const suggest = () => {
    const v = em.value, at = v.indexOf('@');
    sug.textContent = '';
    if (at < 1) { sug.hidden = true; return; }
    const typed = v.slice(at + 1).toLowerCase(), user = v.slice(0, at);
    const list = LG_DOMAINS.filter(d => d.startsWith(typed) && d !== typed);
    sug.hidden = !list.length;
    list.forEach(d => {
      const b = document.createElement('button');
      b.type = 'button'; b.dir = 'ltr'; b.textContent = '@' + d;
      b.onclick = () => { em.value = user + '@' + d; touched = true; paintEmail(); suggest(); pw.focus(); };
      sug.appendChild(b);
    });
  };
  sug.addEventListener('pointerdown', e => e.preventDefault());

  // 3) تذكّر البريد على الجهاز + 4) ترحيب باسم المستخدم
  const saved = ls(LG_KEY);
  if (saved && LG_EMAIL.test(saved)) {
    em.value = saved; rem.checked = true; touched = true;
    if (sub) sub.textContent = t('أهلاً بعودتك يا {n}.').replace('{n}', saved.split('@')[0]);
  }
  paintEmail();
  const vq = new URLSearchParams(location.search).get('verified');
  if (vq !== null) msg.textContent = t(vq === '1' ? 'تم تأكيد بريدك. سجّل الدخول الآن.' : 'رابط التأكيد غير صالح أو منتهي.');
  // إن كانت هناك جلسة فعّالة نرحّب باسم المستخدم (فشل الطلب لا يهم)
  fetch('/api/auth/me', { credentials: 'same-origin' }).then(r => r.ok ? r.json() : null).then(j => {
    if (j?.user) {
      if (sub) sub.textContent = t('أهلاً بعودتك يا {n}.').replace('{n}', j.user.displayName || j.user.email.split('@')[0]);
      if (!location.search.includes('force_login=1')) location.replace('../index.html');
    }
  }).catch(() => { /* لا يوجد خادم */ });

  em.addEventListener('input', () => { if (valid()) touched = true; paintEmail(); suggest(); msg.textContent = ''; });
  em.addEventListener('focus', suggest);
  // التأجيل القصير يمنع انزياح الأزرار تحت إصبعك لحظة الضغط عليها
  em.addEventListener('blur', () => setTimeout(() => { if (document.activeElement === em) return; touched = true; paintEmail(); sug.hidden = true; }, 180));
  // 5) Enter في البريد ينقلك إلى كلمة المرور
  em.addEventListener('keydown', e => { if (e.key === 'Enter' && valid()) { e.preventDefault(); pw.focus(); } });
  clr.onclick = () => { em.value = ''; touched = false; paintEmail(); suggest(); em.focus(); };

  // 6) العين: إظهار/إخفاء كلمة المرور
  eye.addEventListener('pointerdown', e => e.preventDefault());
  eye.onclick = () => {
    const show = pw.type === 'password';
    pw.type = show ? 'text' : 'password';
    eye.classList.toggle('on', show);
    eye.setAttribute('aria-pressed', String(show));
    eye.setAttribute('aria-label', t(show ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور'));
  };

  // 7) تنبيه Caps Lock
  const capsChk = (e: KeyboardEvent) => { caps.hidden = !(e.getModifierState && e.getModifierState('CapsLock')); };
  pw.addEventListener('keydown', capsChk); pw.addEventListener('keyup', capsChk);
  pw.addEventListener('blur', () => setTimeout(() => { if (document.activeElement !== pw) caps.hidden = true; }, 180));

  // 8) اهتزاز الحقل الخاطئ مع رسالة، 9) مؤشر تحميل على زر الدخول
  form.addEventListener('submit', e => {
    e.preventDefault();
    if (busy) return;
    touched = true; paintEmail();
    const bad = !valid() ? em : !pw.value ? pw : null;
    if (bad) {
      msg.textContent = t(bad === em ? 'أدخل بريداً إلكترونياً صحيحاً.' : 'أدخل كلمة المرور.');
      form.classList.remove('shake'); void form.offsetWidth; if (!RM) form.classList.add('shake');
      bad.focus(); return;
    }
    busy = true; go.disabled = true; go.classList.add('ld'); msg.textContent = '';
    ls(LG_KEY, rem.checked ? em.value.trim() : '');
    sendLogin(em.value.trim(), pw.value, rem.checked)
      .then(r => {
        if (r.ok) {
          msg.classList.remove('err'); msg.textContent = t(r.restored ? 'تمت استعادة حساب المالك وتسجيل دخولك. غيّر كلمة السر الآن.' : 'تم تسجيل الدخول.');
          pw.value = '';
          setTimeout(() => { location.href = ROOT_HOME; }, r.restored ? 1800 : 500);
          return;
        }
        msg.classList.add('err'); msg.textContent = t(ERR[r.error] ?? ERR.network);
        if (r.error === 'pending') {
          const a = document.createElement('a'); a.className = 'lk'; a.href = 'register.html?verify=' + encodeURIComponent(em.value.trim()); a.textContent = t('إدخال رمز التأكيد');
          msg.append(' ', a);
        }
        form.classList.remove('shake'); void form.offsetWidth; if (!RM) form.classList.add('shake');
        busy = false; go.disabled = false; go.classList.remove('ld'); pw.focus();
      });
  });

  // 10) تركيز تلقائي على الجوال لا (يفتح لوحة المفاتيح)، وعلى الحاسوب نعم
  if (matchMedia('(pointer:fine)').matches) (em.value ? pw : em).focus();
}
