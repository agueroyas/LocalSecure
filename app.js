const byId = (id) => document.getElementById(id);

const patterns = [
  { regex: /\b(api[_-]?key|secret|token)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{16,})["']?/gi, replacement: (_match, label) => `${label}=[REDACTED_SECRET]` },
  { regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replacement: '[REDACTED_EMAIL]' },
  { regex: /\b(?:\d[ -]*?){13,19}\b/g, replacement: '[REDACTED_NUMBER]' },
];

byId('scan-btn').addEventListener('click', () => {
  const input = byId('input-text').value;
  const result = patterns.reduce((text, { regex, replacement }) => text.replace(regex, replacement), input);
  byId('output-text').textContent = result || 'لم يتم إدخال نص.';
  byId('copy-btn').disabled = !result;
  byId('scan-status').textContent = input ? 'اكتمل الفحص محلياً.' : 'اكتب نصاً أولاً لبدء الفحص.';
});

byId('copy-btn').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(byId('output-text').textContent);
    byId('scan-status').textContent = 'تم نسخ النتيجة.';
  } catch {
    byId('scan-status').textContent = 'تعذر النسخ تلقائياً. حدّد النتيجة وانسخها يدوياً.';
  }
});

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
}

byId('encrypt-btn').addEventListener('click', async () => {
  const status = byId('encrypt-status');
  const button = byId('encrypt-btn');
  const file = byId('file-input').files?.[0];
  const password = byId('secret-key').value;
  if (!file) { status.textContent = 'اختر ملفاً أولاً.'; return; }
  if ([...password].length < 12) { status.textContent = 'استخدم كلمة مرور من 12 حرفاً على الأقل.'; return; }
  if (!globalThis.crypto?.subtle) { status.textContent = 'التشفير يتطلب اتصالاً آمناً (HTTPS) ومتصفحاً حديثاً.'; return; }

  button.disabled = true;
  status.textContent = 'جارٍ تشفير الملف على جهازك…';
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, await file.arrayBuffer()));
    // File layout: 8-byte magic, 16-byte salt, 12-byte IV, then authenticated ciphertext.
    const header = new Uint8Array(36);
    header.set(new TextEncoder().encode('LSECURE1'), 0);
    header.set(salt, 8);
    header.set(iv, 24);
    const blob = new Blob([header, encrypted], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${file.name}.lsec`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    status.textContent = `تم التشفير والتنزيل (${formatBytes(blob.size)}). احتفظ بكلمة المرور لاستعادة الملف.`;
  } catch (error) {
    console.error('Local encryption failed:', error);
    status.textContent = 'تعذر تشفير الملف. جرّب ملفاً أصغر أو متصفحاً حديثاً.';
  } finally {
    button.disabled = false;
  }
});

function formatBytes(size) {
  if (size < 1024) return `${size} بايت`;
  return `${(size / 1024 / 1024).toFixed(2)} ميجابايت`;
}

