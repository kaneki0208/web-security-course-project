'use strict';

const byId = id => document.getElementById(id);
const state = {pages: new Map(), findings: [], coverage: [], sources: [], selected: '', demo: false, audit: false};
const viewLinks = [...document.querySelectorAll('[data-view]')];
const targetFilter = byId('target-filter');
const toolFilter = byId('tool-filter');
const typeFilter = byId('type-filter');
const reviewFilter = byId('review-filter');
const pageSearch = byId('page-search');
const findingSearch = byId('finding-search');
const pageRows = byId('page-rows');
const findingRows = byId('finding-rows');
const coverageCells = [...byId('coverage-rows').querySelectorAll('td')];
const dialog = byId('import-dialog');
const importForm = byId('import-form');
const limit = 24 * 1024 * 1024;

function element(tag, value = '', className = '') {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}

function button(label, className, action) {
  const node = element('button', label, className);
  node.type = 'button';
  node.addEventListener('click', action);
  return node;
}

function chips(values, tone = () => '') {
  if (!values.length) return element('span', '—', 'detail-note');
  const list = element('div', '', 'chips');
  for (const value of values) list.append(element('span', value, `chip ${tone(value)}`));
  return list;
}

function httpTone(status) {
  if (status >= 400) return 'bad';
  return status >= 300 ? 'warning' : 'ok';
}

function tableEmpty(columns, message) {
  const row = element('tr');
  const cell = element('td', message, 'empty');
  cell.colSpan = columns;
  row.append(cell);
  return row;
}

function matches(query, values) {
  return values.some(value => value.toLocaleLowerCase().includes(query));
}

function pageParameters(page) {
  return [...new Set([...page.query, ...page.forms.flatMap(form => form.fields.map(field => field.name))])];
}

function view() {
  const reports = location.hash === '#reports';
  byId('pages-view').hidden = reports;
  byId('reports-view').hidden = !reports;
  byId('view-title').textContent = reports ? '扫描报告' : '页面清单';
  byId('view-description').textContent = reports
    ? '按工具、漏洞类型和复核状态查看导入的检测记录。'
    : '查看归档页面的访问状态、表单参数和链接关系。';
  for (const link of viewLinks) {
    if (link.dataset.view === (reports ? 'reports' : 'pages')) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

function showNotice(message, error = false) {
  const notice = byId('notice');
  notice.hidden = !message;
  notice.textContent = message;
  notice.classList.toggle('error', error);
}

function selectPage(url, clearSearch) {
  state.selected = url;
  if (clearSearch) pageSearch.value = '';
  renderPages();
  byId('selected-page-heading')?.focus();
}

function renderPageList(pages) {
  const rows = document.createDocumentFragment();
  for (const page of pages) {
    const row = element('tr');
    row.classList.toggle('active-row', page.url === state.selected);
    const identity = element('td');
    const title = button(page.title || '无标题页面', 'table-link', () => selectPage(page.url, false));
    title.setAttribute('aria-controls', 'page-details');
    identity.append(title, element('span', page.url, 'url'));
    const status = element('td');
    status.append(chips(page.statuses, httpTone));
    const params = element('td');
    params.append(chips(pageParameters(page)));
    row.append(identity, status, params);
    rows.append(row);
  }
  if (!pages.length) rows.append(tableEmpty(3, state.pages.size ? '没有符合条件的页面。' : '导入 HAR 后，页面访问记录会显示在这里。'));
  pageRows.replaceChildren(rows);
  byId('page-summary').textContent = `显示 ${pages.length} / ${state.pages.size} 个页面`;
}

function detailBlock(title) {
  const section = element('section', '', 'detail-block');
  section.append(element('h3', title));
  return section;
}

function linkList(urls) {
  if (!urls.length) return element('p', '无记录', 'detail-note');
  const list = element('ul', '', 'link-list');
  for (const url of urls) {
    const item = element('li');
    const target = state.pages.get(url);
    if (target) item.append(button(target.title || '无标题页面', 'node-link', () => selectPage(url, true)));
    item.append(element('span', url, 'url'));
    if (!target) item.append(element('span', '未记录此页面的响应', 'detail-note'));
    list.append(item);
  }
  return list;
}

function renderPageDetails(page) {
  const panel = byId('page-details');
  const heading = element('div');
  const title = element('h2', page ? (page.title || '无标题页面') : '页面详情');
  title.id = 'selected-page-heading';
  title.tabIndex = -1;
  heading.append(title);
  panel.replaceChildren(heading);
  if (!page) {
    panel.append(element('p', '从清单选择一个页面。', 'detail-note detail-block'));
    return;
  }
  heading.append(element('span', page.url, 'url'));

  const info = detailBlock('请求参数');
  const query = element('dl');
  const names = element('dd');
  names.append(chips(page.query));
  query.append(element('dt', 'URL 查询参数'), names);
  info.append(query);
  const forms = detailBlock(`表单 · ${page.forms.length}`);
  const list = element('ul', '', 'form-list');
  for (const form of page.forms) {
    const item = element('li');
    item.append(element('strong', form.method), element('span', form.action || '范围外或无有效地址', 'url'),
      chips(form.fields.map(field => `${field.name} · ${field.type}`)));
    list.append(item);
  }
  forms.append(page.forms.length ? list : element('p', page.has_html ? '页面中没有表单。' : '归档中缺少 HTML 正文。', 'detail-note'));

  const relations = detailBlock('链接关系');
  const incoming = [...state.pages.values()].filter(from => from.links.includes(page.url)).map(from => from.url);
  relations.append(element('p', `入链 · ${incoming.length}`, 'link-heading'), linkList(incoming),
    element('p', `出链 · ${page.links.length}`, 'link-heading'), linkList(page.links));
  panel.append(info, forms, relations);
}

function renderPages() {
  const query = pageSearch.value.trim().toLocaleLowerCase();
  const pages = [...state.pages.values()].filter(page => matches(query, [page.title, page.url, ...pageParameters(page)]));
  const selected = pages.find(page => page.url === state.selected) || pages[0];
  state.selected = selected?.url || '';
  renderPageList(pages);
  renderPageDetails(selected);
}

function setOptions(select, all, values) {
  const selected = select.value;
  const distinct = [...new Set(values.filter(Boolean))].sort();
  select.replaceChildren(new Option(all, ''), ...distinct.map(value => new Option(value, value)));
  if ([...select.options].some(option => option.value === selected)) select.value = selected;
}

function findingRow(finding) {
  const row = element('tr');
  const body = element('td');
  const details = element('details');
  const detail = element('div', '', 'report-detail');
  detail.append(element('p', `来源文件 · ${finding.source}`));
  if (finding.target) detail.append(element('p', `目标 · ${finding.target}`));
  if (finding.method) detail.append(element('p', `HTTP 方法 · ${finding.method}`));
  if (finding.parameter) detail.append(element('p', `参数 · ${finding.parameter}`));
  if (finding.reference) detail.append(element('p', `证据位置 · ${finding.reference}`));
  detail.append(element('p', finding.evidence || '没有导入证据摘要。'));
  details.append(element('summary', finding.title), detail);
  body.append(details, element('span', finding.url, 'url'));
  const review = element('td');
  const reviewTone = {'待复核': 'pending', '已确认': 'confirmed', '漏报': 'missed'};
  review.append(chips([finding.review], name => reviewTone[name] || ''));
  row.append(body, element('td', finding.tool), element('td', finding.type), element('td', finding.severity || '—'), review);
  return row;
}

function renderFindings() {
  const query = findingSearch.value.trim().toLocaleLowerCase();
  const findings = state.findings.filter(finding =>
    (!targetFilter.value || finding.target === targetFilter.value) &&
    (!toolFilter.value || finding.tool === toolFilter.value) &&
    (!typeFilter.value || finding.type === typeFilter.value) &&
    (!reviewFilter.value || finding.review === reviewFilter.value) &&
    matches(query, [finding.title, finding.url, finding.parameter]));
  const rows = document.createDocumentFragment();
  for (const finding of findings) rows.append(findingRow(finding));
  if (!findings.length) rows.append(tableEmpty(5, state.findings.length ? '没有符合筛选条件的记录。' : '导入报告后，检测记录会显示在这里。'));
  findingRows.replaceChildren(rows);
  byId('finding-summary').textContent = `显示 ${findings.length} / ${state.findings.length} 条记录`;
}

function renderCoverage() {
  const tones = {'已有报告': '', '已核对覆盖范围': 'confirmed', '未覆盖': 'pending'};
  for (const cell of coverageCells) {
    const {tool, target} = cell.dataset;
    const rows = state.coverage.filter(row => row.tool === tool && row.target === target);
    cell.replaceChildren();
    if (!rows.length) {
      cell.append(chips(['待补证据'], () => 'pending'));
      continue;
    }
    for (const row of rows) {
      const details = element('details');
      details.append(element('summary', row.state, `chip ${tones[row.state]}`));
      const note = element('div', '', 'report-detail');
      note.append(element('p', `来源文件 · ${row.source}`));
      if (row.scope) note.append(element('p', `范围 · ${row.scope}`));
      if (row.reference) note.append(element('p', `依据 · ${row.reference}`));
      details.append(note);
      cell.append(details);
    }
  }
}

function renderAll() {
  const source = byId('source-line');
  source.replaceChildren(element('span', '数据来源'));
  if (state.demo) source.append(element('span', '示例数据 · 仅用于演示', 'file-label sample-label'));
  else if (!state.sources.length) source.append(element('span', '尚未导入文件', 'file-label'));
  else for (const name of state.sources) source.append(element('span', name, 'file-label'));
  byId('page-count').textContent = state.pages.size;
  byId('link-count').textContent = [...state.pages.values()].reduce((count, page) => count + page.links.length, 0);
  byId('finding-count').textContent = state.findings.length;
  byId('review-count').textContent = state.findings.filter(item => item.review === '待复核').length;
  for (const [filter, label, field] of [[targetFilter, '全部目标', 'target'], [toolFilter, '全部工具', 'tool'], [typeFilter, '全部类型', 'type'], [reviewFilter, '全部状态', 'review']]) {
    setOptions(filter, label, state.findings.map(finding => finding[field]));
  }
  byId('load-example').hidden = state.demo || state.sources.length > 0;
  byId('load-audit').hidden = state.audit;
  byId('export-data').hidden = !state.sources.length || !(state.pages.size || state.findings.length || state.coverage.length);
  byId('clear-data').hidden = !state.demo && !state.sources.length;
  renderPages();
  renderFindings();
  renderCoverage();
}

function clearRecords() {
  state.pages.clear();
  state.findings = [];
  state.coverage = [];
  state.sources = [];
  state.selected = '';
  state.demo = false;
  state.audit = false;
  for (const field of [pageSearch, findingSearch, targetFilter, toolFilter, typeFilter, reviewFilter]) field.value = '';
}

function addRecords(data, source) {
  for (const page of data.pages) {
    const previous = state.pages.get(page.url);
    if (!previous) {
      state.pages.set(page.url, page);
      continue;
    }
    const latest = page.has_html ? page : previous;
    state.pages.set(page.url, {...latest,
      statuses: [...new Set([...previous.statuses, ...page.statuses])],
      links: [...new Set([...previous.links, ...page.links])],
    });
  }
  for (const finding of data.findings) state.findings.push({...finding, source: finding.source || source});
  for (const row of data.coverage) state.coverage.push({...row, source: row.source || source});
}

async function loadExample() {
  const loadButton = byId('load-example');
  loadButton.disabled = true;
  try {
    const response = await fetch('/api/example');
    if (!response.ok) throw new Error('示例无法加载。');
    const data = await response.json();
    if (state.sources.length) return;
    clearRecords();
    state.demo = true;
    addRecords(data, '内置示例');
    showNotice('');
    renderAll();
  } catch {
    showNotice('示例无法加载。请重新打开工作台或导入自己的文件。', true);
  } finally {
    loadButton.disabled = false;
  }
}

async function loadSourceAudit() {
  const control = byId('load-audit');
  control.disabled = true;
  try {
    const response = await fetch('/api/source-audit');
    if (!response.ok) throw new Error('源码审查记录无法加载。');
    const data = await response.json();
    if (state.demo) clearRecords();
    const source = 'source-audit.json · 源码审查';
    state.audit = true;
    state.sources.push(source);
    addRecords(data, source);
    showNotice(`已载入 ${data.findings.length} 条源码审查记录。`);
    renderAll();
    for (const field of [findingSearch, targetFilter, typeFilter, reviewFilter]) field.value = '';
    toolFilter.value = '静态代码审查';
    renderFindings();
    location.hash = '#reports';
  } catch {
    showNotice('源码审查记录无法加载。', true);
  } finally {
    control.disabled = false;
  }
}

function exportRecords() {
  const report = {schema: 'course-evidence/v1', pages: [...state.pages.values()],
    findings: state.findings, coverage: state.coverage};
  const content = new Blob([JSON.stringify(report, null, 2) + '\n'], {type: 'application/json'});
  const url = URL.createObjectURL(content);
  const link = element('a');
  link.href = url;
  link.download = 'course-evidence.json';
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function importError(message) {
  byId('import-error').hidden = !message;
  byId('import-error').textContent = message;
}

importForm.addEventListener('submit', async event => {
  event.preventDefault();
  importError('');
  const file = byId('document').files[0];
  if (!file) return;
  if (file.size > limit) {
    importError('文件超过 24 MB，请缩小导出范围。');
    return;
  }
  const submit = byId('submit-import');
  submit.disabled = true;
  try {
    const response = await fetch('/api/import', {method: 'POST', body: new FormData(importForm)});
    const data = await response.json();
    if (!response.ok) {
      importError(data.error || '无法导入该文件。');
      return;
    }
    if (state.demo) clearRecords();
    const source = `${file.name} · ${data.kind}`;
    state.sources.push(source);
    addRecords(data, source);
    showNotice(`已导入 ${data.pages.length} 个页面、${data.findings.length} 条检测记录和 ${data.coverage.length} 条覆盖记录。${data.notes.join(' ')}`);
    renderAll();
    if (data.pages.length) location.hash = '#pages';
    else if (data.findings.length || data.coverage.length || data.kind === 'ZAP Traditional JSON') location.hash = '#reports';
    dialog.close();
    importForm.reset();
  } catch {
    importError('导入请求没有完成，请确认本地工作台仍在运行。');
  } finally {
    submit.disabled = false;
  }
});

byId('open-import').addEventListener('click', () => {
  importError('');
  dialog.showModal();
});
byId('close-import').addEventListener('click', () => dialog.close());
byId('load-example').addEventListener('click', loadExample);
byId('load-audit').addEventListener('click', loadSourceAudit);
byId('export-data').addEventListener('click', exportRecords);
byId('clear-data').addEventListener('click', () => {
  clearRecords();
  showNotice('');
  renderAll();
  byId('load-example').focus();
});
pageSearch.addEventListener('input', renderPages);
findingSearch.addEventListener('input', renderFindings);
for (const filter of [targetFilter, toolFilter, typeFilter, reviewFilter]) filter.addEventListener('change', renderFindings);
window.addEventListener('hashchange', view);
view();
renderAll();
loadExample();
