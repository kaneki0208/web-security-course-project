const token = () => document.querySelector('meta[name="csrf-token"]').content;
document.querySelectorAll('[data-open-dialog]').forEach(button => {
  button.addEventListener('click', () => document.getElementById(button.dataset.openDialog).showModal());
});
document.querySelectorAll('[data-close-dialog]').forEach(button => {
  button.addEventListener('click', () => button.closest('dialog').close());
});
document.querySelectorAll('dialog[data-auto-open="true"]').forEach(dialog => dialog.showModal());

const form = document.querySelector('#booking-form');
if (form) form.addEventListener('submit', async event => {
  event.preventDefault();
  const message = document.querySelector('#booking-message');
  const submit = form.querySelector('[type="submit"]');
  message.hidden = true;
  submit.disabled = true;
  submit.textContent = '正在提交…';
  try {
    const response = await fetch('/api/bookings', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':token()}, body:JSON.stringify({equipment_id:Number(form.equipment_id.value),purpose:form.purpose.value})});
    if (response.status === 401) throw new Error('登录已失效，请重新登录后提交。');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '提交失败，请稍后重试。');
    location.assign('/bookings?created=' + encodeURIComponent(data.id));
  } catch(error) {
    message.textContent = error.message;
    message.hidden = false;
    submit.disabled = false;
    submit.textContent = '提交申请';
  }
});

let detailRequest;
document.querySelectorAll('.detail').forEach(button => button.addEventListener('click', async () => {
  const dialog = document.querySelector('#detail-dialog');
  const panel = document.querySelector('#booking-detail');
  if (detailRequest) detailRequest.abort();
  detailRequest = new AbortController();
  panel.textContent = '正在读取申请…';
  dialog.showModal();
  try {
    const response = await fetch('/api/bookings/' + button.dataset.id, {signal:detailRequest.signal});
    if (!response.ok) throw new Error(response.status===403 ? '你没有查看这条申请的权限。' : '无法读取申请，请重新登录或稍后重试。');
    const data = await response.json();
    const list = document.createElement('dl');
    list.className = 'detail-data';
    const date = new Date(data.created_at.replace(' ', 'T') + 'Z');
    const fields = [['申请编号', '#' + data.id], ['申请人', data.username], ['借用设备', data.name], ['借用用途', data.purpose], ['申请状态', data.status], ['申请时间', date.toLocaleString('zh-CN', {timeZone:'Asia/Shanghai', hour12:false})]];
    for (const [label,value] of fields) {
      const dt = document.createElement('dt'); dt.textContent = label;
      const dd = document.createElement('dd'); dd.textContent = value;
      list.append(dt,dd);
    }
    panel.replaceChildren(list);
  } catch(error) {
    if (error.name !== 'AbortError') panel.textContent = error.message;
  }
}));
