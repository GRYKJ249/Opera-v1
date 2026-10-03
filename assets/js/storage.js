const $ = (id) => document.getElementById(id);
let current = '';
const api = async (path, init = {}) => {
  const r = await fetch(path, { credentials: 'same-origin', ...init });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'تعذر تنفيذ العملية');
  return data;
};
const clean = (value) => String(value || '').split('/').filter(Boolean).filter(p => p !== '.' && p !== '..').join('/');
const pathOf = (name) => clean(current ? `${current}/${name}` : name);
const setStatus = (text, error = false) => { $('status').textContent = text || ''; $('status').style.color = error ? '#ff8ba7' : ''; };
const render = async () => {
  setStatus('جاري تحميل الملفات…');
  $('crumb').textContent = '/' + (current ? current + '/' : '');
  const data = await api(`/api/storage/list?path=${encodeURIComponent(current)}`);
  const rows = $('files'); rows.replaceChildren();
  for (const item of data.files) {
    const name = item.name || 'بدون اسم';
    const isDir = item.href.endsWith('/');
    const tr = document.createElement('tr');
    const nameTd = document.createElement('td');
    const button = document.createElement('button'); button.className = 'file-link'; button.textContent = (isDir ? '📁 ' : '📄 ') + name;
    if (isDir) button.onclick = () => { current = pathOf(name); render().catch(showError); };
    else { button.onclick = () => { window.location.href = `/api/storage/download?path=${encodeURIComponent(pathOf(name))}`; }; }
    nameTd.append(button); tr.append(nameTd);
    const typeTd = document.createElement('td'); typeTd.textContent = isDir ? 'مجلد' : 'ملف'; tr.append(typeTd);
    const actionTd = document.createElement('td'); actionTd.className = 'file-actions';
    if (!isDir) { const download = document.createElement('a'); download.textContent = 'تنزيل'; download.href = `/api/storage/download?path=${encodeURIComponent(pathOf(name))}`; download.download = name; actionTd.append(download); }
    const del = document.createElement('button'); del.textContent = 'حذف'; del.onclick = async () => { if (!confirm(`حذف ${name}؟`)) return; try { await api(`/api/storage/delete?path=${encodeURIComponent(pathOf(name))}`, { method: 'DELETE' }); await render(); } catch (e) { showError(e); } }; actionTd.append(del); tr.append(actionTd); rows.append(tr);
  }
  $('empty').hidden = data.files.length !== 0; setStatus(data.files.length ? `${data.files.length} عنصر` : '');
};
const showError = (e) => setStatus(e?.message || 'حدث خطأ', true);
$('up').onclick = () => { if (!current) return; current = current.split('/').slice(0, -1).join('/'); render().catch(showError); };
$('upload').onchange = async (e) => { const file = e.target.files?.[0]; if (!file) return; try { setStatus('جاري رفع الملف…'); await api(`/api/storage/upload?path=${encodeURIComponent(pathOf(file.name))}`, { method: 'PUT', headers: { 'Content-Type': file.type || 'application/octet-stream' }, body: file }); await render(); } catch (err) { showError(err); } finally { e.target.value = ''; } };
$('new-folder').onclick = () => { $('folder-name').value = ''; $('folder-modal').hidden = false; $('folder-name').focus(); };
$('cancel-folder').onclick = () => { $('folder-modal').hidden = true; };
$('create-folder').onclick = async () => { const name = clean($('folder-name').value); if (!name || name.includes('/')) return setStatus('اكتب اسم مجلد صحيحاً', true); try { await api('/api/storage/folder', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: pathOf(name) }) }); $('folder-modal').hidden = true; await render(); } catch (e) { showError(e); } };
$('logout').onclick = async () => { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); location.href = '/'; };
api('/api/auth/me').then(({ user }) => { $('welcome').textContent = `مساحتك الخاصة — ${user.displayName || user.email}`; return render(); }).catch(() => { location.href = '../pages/login.html'; });
