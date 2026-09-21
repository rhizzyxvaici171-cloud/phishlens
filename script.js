const urlInput = document.getElementById('urlInput');
const checkBtn = document.getElementById('checkBtn');
const output = document.getElementById('output');
const errorBox = document.getElementById('errorBox');
const scoreRing = document.getElementById('scoreRing');
const scoreValue = document.getElementById('scoreValue');
const resultLevel = document.getElementById('resultLevel');
const resultDomain = document.getElementById('resultDomain');
const findingsList = document.getElementById('findings');

const LEVEL_COLOR = {
  low: 'var(--safe)',
  medium: 'var(--amber)',
  high: 'var(--red)',
  critical: 'var(--red)',
};

const LEVEL_LABEL = {
  low: 'Looks clean',
  medium: 'Worth a second look',
  high: 'Several red flags',
  critical: 'Serious red flags',
};

const SEVERITY_ICON = {
  critical: '⛔',
  high: '⚠',
  medium: '◆',
  low: 'ℹ',
};

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function renderResult(result) {
  errorBox.hidden = true;
  output.hidden = false;

  scoreValue.textContent = result.score;
  scoreRing.style.borderColor = LEVEL_COLOR[result.level];
  scoreRing.style.color = LEVEL_COLOR[result.level];

  resultLevel.textContent = LEVEL_LABEL[result.level];
  resultLevel.style.color = LEVEL_COLOR[result.level];
  resultDomain.textContent = result.hostname;

  findingsList.innerHTML = '';

  if (result.findings.length === 0) {
    const li = document.createElement('li');
    li.className = 'finding severity-low';
    li.innerHTML = `<span class="finding-icon">✓</span><span class="finding-text"><strong>No known red flags found</strong><span>This checks structural patterns only, it can't confirm a site is legitimate, verify what you'd expect to independently for anything sensitive.</span></span>`;
    findingsList.appendChild(li);
  } else {
    for (const f of result.findings) {
      const li = document.createElement('li');
      li.className = `finding severity-${f.severity}`;
      li.innerHTML = `<span class="finding-icon">${SEVERITY_ICON[f.severity]}</span><span class="finding-text"><strong>${escapeHtml(f.title)}</strong><span>${escapeHtml(f.detail)}</span></span>`;
      findingsList.appendChild(li);
    }
  }
}

function renderError(message) {
  output.hidden = true;
  errorBox.hidden = false;
  errorBox.textContent = message;
}

function runCheck() {
  const value = urlInput.value.trim();
  if (!value) {
    output.hidden = true;
    errorBox.hidden = true;
    return;
  }
  const result = analyzeUrl(value);
  if (!result.ok) {
    renderError(result.error);
  } else {
    renderResult(result);
  }
}

checkBtn.addEventListener('click', runCheck);
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runCheck();
});

let debounceTimer;
urlInput.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(runCheck, 350);
});
