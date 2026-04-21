// Dashboard report assistant (LLM triage via /api/assistant/chat).
DashboardApp._assistantConversation = [];
DashboardApp._assistantSessionId = '';
DashboardApp._assistantReportPath = '';

DashboardApp.resetAssistantConversation = function () {
    DashboardApp._assistantConversation = [];
    DashboardApp._assistantSessionId = '';
};

/** Drop assistant DOM and in-memory state when navigating to another report or format. */
DashboardApp.resetAssistantPanelForModalNavigation = function () {
    DashboardApp.resetAssistantConversation();
    DashboardApp._assistantReportPath = '';
    if (typeof DashboardApp.teardownExecutivePreviewCharts === 'function') {
        DashboardApp.teardownExecutivePreviewCharts();
    }
    const wrapper = document.getElementById('report-modal-content');
    if (wrapper) {
        wrapper.querySelectorAll('.oasis-assistant-synthetic-wrap').forEach(function (el) {
            if (el.parentNode) {
                el.parentNode.removeChild(el);
            }
        });
        wrapper.querySelectorAll('.oasis-assistant-panel').forEach(function (el) {
            if (el.parentNode) {
                el.parentNode.removeChild(el);
            }
        });
    }
};

DashboardApp._newAssistantSessionId = function () {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
};

DashboardApp._trimAssistantMessages = function (messages) {
    const cap = DashboardApp.ASSISTANT_MAX_MESSAGES_CAP || 40;
    const arr = Array.isArray(messages) ? messages : [];
    if (arr.length <= cap) {
        return arr.slice();
    }
    return arr.slice(arr.length - cap);
};

DashboardApp._assistantMessagesForApi = function () {
    return DashboardApp._assistantConversation.map(function (m) {
        return {
            role: m.role,
            content: typeof m.content === 'string' ? m.content : '',
            at: typeof m.at === 'string' ? m.at : '',
        };
    });
};

DashboardApp._truncateAssistantLabel = function (text, maxLen) {
    const s = String(text || '');
    const cap = typeof maxLen === 'number' && maxLen > 4 ? maxLen : 72;
    if (s.length <= cap) {
        return s;
    }
    return s.slice(0, cap - 1) + '…';
};

/** True for _executive_summary report path (md or json) under security-reports. */
DashboardApp.isExecutiveSummaryPath = function (reportPath) {
    return /(^|\/)_executive_summary\.(json|md)$/i.test(String(reportPath || ''));
};

/** Map sibling md/json paths (same stem) so assistant API sees the canonical JSON path. */
DashboardApp.canonicalAssistantReportPath = function (reportPath) {
    const r = String(reportPath || '').trim();
    if (!r) {
        return r;
    }
    if (/\.json$/i.test(r)) {
        return r;
    }
    if (/\.md$/i.test(r)) {
        return r.replace(/\/md\//i, '/json/').replace(/\.md$/i, '.json');
    }
    return r;
};

/** Scoped localStorage key so each canonical report prefers its own last model choice. */
DashboardApp._assistantChatModelStorageKey = function (canonicalReportPath) {
    const r = String(canonicalReportPath || '').trim();
    return r ? 'oasis_assistant_chat_model::' + r : 'oasis_assistant_chat_model';
};

/** Prefer analysis model fields from canonical report JSON (executive or vulnerability). */
DashboardApp.preferredChatModelFromReportPayload = function (payload) {
    if (!payload || typeof payload !== 'object') {
        return '';
    }
    const keys = ['model_name', 'deep_model', 'small_model', 'model'];
    for (let i = 0; i < keys.length; i++) {
        const v = payload[keys[i]];
        if (typeof v === 'string' && v.trim()) {
            return v.trim();
        }
    }
    return '';
};

/**
 * Fill file/chunk/finding dropdowns from a vulnerability report payload (shared by single-report and executive scope).
 */
DashboardApp.populateAssistantFindingSelectorsFromPayload = function (panelRoot, txt, payload) {
    const selFi = panelRoot.querySelector('#oasis-assistant-fi');
    const selCi = panelRoot.querySelector('#oasis-assistant-ci');
    const selGi = panelRoot.querySelector('#oasis-assistant-gi');
    if (!selFi || !selCi || !selGi) {
        return;
    }
    const noneText = txt('findingNoneOption', '— none —');
    function resetSelect(sel) {
        DashboardApp._clearElement(sel);
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = noneText;
        sel.appendChild(opt);
    }
    const files =
        payload && typeof payload === 'object' && Array.isArray(payload.files) ? payload.files : [];
    panelRoot._oasisAssistantFiles = files;
    resetSelect(selFi);
    resetSelect(selCi);
    resetSelect(selGi);
    files.forEach(function (f, idx) {
        const opt = document.createElement('option');
        opt.value = String(idx);
        const fp = f && typeof f.file_path === 'string' ? f.file_path : '(' + idx + ')';
        opt.textContent = DashboardApp._truncateAssistantLabel(fp, 72);
        selFi.appendChild(opt);
    });
};

/** Wire cascading file/chunk/finding changes once per panel. */
DashboardApp._assistantBindFindingSelectorEvents = function (panelRoot, txt) {
    if (panelRoot.dataset.oasisFindingSelectorEvents === '1') {
        return;
    }
    panelRoot.dataset.oasisFindingSelectorEvents = '1';
    const selFi = panelRoot.querySelector('#oasis-assistant-fi');
    const selCi = panelRoot.querySelector('#oasis-assistant-ci');
    const selGi = panelRoot.querySelector('#oasis-assistant-gi');
    if (!selFi || !selCi || !selGi) {
        return;
    }
    const noneText = txt('findingNoneOption', '— none —');

    function selectedIndex(sel) {
        const v = sel && sel.value;
        if (v === '' || v === undefined || v === null) {
            return NaN;
        }
        const n = Number(v);
        return Number.isFinite(n) ? n : NaN;
    }

    function resetSelect(sel) {
        DashboardApp._clearElement(sel);
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = noneText;
        sel.appendChild(opt);
    }

    function chunkOptionLabel(chunk, index) {
        let base = txt('findingChunkLabel', 'Chunk') + ' ' + (index + 1);
        if (chunk && chunk.start_line != null && chunk.end_line != null) {
            base += ' (lines ' + chunk.start_line + '–' + chunk.end_line + ')';
        }
        return DashboardApp._truncateAssistantLabel(base, 96);
    }

    function renderChunksForFile(files, fi) {
        resetSelect(selCi);
        resetSelect(selGi);
        if (!Number.isFinite(fi) || fi < 0 || fi >= files.length) {
            return;
        }
        const chunks = files[fi] && Array.isArray(files[fi].chunk_analyses) ? files[fi].chunk_analyses : [];
        chunks.forEach(function (ch, j) {
            const opt = document.createElement('option');
            opt.value = String(j);
            opt.textContent = chunkOptionLabel(ch, j);
            selCi.appendChild(opt);
        });
    }

    function renderFindingsForChunk(files, fi, ci) {
        resetSelect(selGi);
        if (!Number.isFinite(fi) || fi < 0 || fi >= files.length) {
            return;
        }
        const chunks = files[fi].chunk_analyses || [];
        if (!Number.isFinite(ci) || ci < 0 || ci >= chunks.length) {
            return;
        }
        const findings = chunks[ci].findings || [];
        findings.forEach(function (fd, k) {
            const opt = document.createElement('option');
            opt.value = String(k);
            const title =
                fd && typeof fd.title === 'string' && fd.title.trim()
                    ? fd.title.trim()
                    : txt('findingFindingLabel', 'Finding') + ' ' + (k + 1);
            opt.textContent = DashboardApp._truncateAssistantLabel(title, 88);
            selGi.appendChild(opt);
        });
    }

    function onFileChange() {
        const files = panelRoot._oasisAssistantFiles || [];
        const fi = selectedIndex(selFi);
        if (!Number.isFinite(fi) || fi < 0 || fi >= files.length) {
            resetSelect(selCi);
            resetSelect(selGi);
            return;
        }
        renderChunksForFile(files, fi);
    }

    function onChunkChange() {
        const files = panelRoot._oasisAssistantFiles || [];
        const fi = selectedIndex(selFi);
        const ci = selectedIndex(selCi);
        renderFindingsForChunk(files, fi, ci);
    }

    selFi.addEventListener('change', onFileChange);
    selCi.addEventListener('change', onChunkChange);
};

/**
 * Populate file/chunk/finding dropdowns from one report JSON; wire cascading changes.
 */
DashboardApp.wireAssistantFindingSelectors = function (panelRoot, txt, reportPath) {
    if (typeof DashboardApp.fetchReportJsonPayload !== 'function') {
        return;
    }
    DashboardApp.fetchReportJsonPayload(reportPath)
        .then(function (payload) {
            if (!payload || typeof payload !== 'object') {
                return;
            }
            DashboardApp.populateAssistantFindingSelectorsFromPayload(panelRoot, txt, payload);
            DashboardApp._assistantBindFindingSelectorEvents(panelRoot, txt);
        })
        .catch(function () {
            /* keep none-only selects */
        });
};

/**
 * Executive aggregate: vuln-report list from preview meta, then same file/chunk/finding drill-down.
 */
DashboardApp.wireAssistantExecutiveFindingSelectors = function (panelRoot, txt, rawMetaPath) {
    const selVi = panelRoot.querySelector('#oasis-assistant-vi');
    if (!selVi || typeof DashboardApp.fetchExecutivePreviewMeta !== 'function') {
        return;
    }
    const noneText = txt('findingNoneOption', '— none —');
    DashboardApp.populateAssistantFindingSelectorsFromPayload(panelRoot, txt, { files: [] });
    DashboardApp._assistantBindFindingSelectorEvents(panelRoot, txt);

    function fillVulnReportList(rows) {
        DashboardApp._clearElement(selVi);
        const opt0 = document.createElement('option');
        opt0.value = '';
        opt0.textContent = noneText;
        selVi.appendChild(opt0);
        rows.forEach(function (row) {
            const rel =
                row && typeof row.relative_path === 'string' ? row.relative_path.trim() : '';
            if (!rel) {
                return;
            }
            const opt = document.createElement('option');
            opt.value = rel;
            const lb =
                row && typeof row.label === 'string' && row.label.trim()
                    ? row.label.trim()
                    : rel;
            opt.textContent = DashboardApp._truncateAssistantLabel(lb, 72);
            selVi.appendChild(opt);
        });
    }

    DashboardApp.fetchExecutivePreviewMeta(String(rawMetaPath || '').trim())
        .then(function (meta) {
            const rows =
                meta && Array.isArray(meta.vulnerability_reports) ? meta.vulnerability_reports : [];
            fillVulnReportList(rows);
        })
        .catch(function () {
            fillVulnReportList([]);
        });

    if (panelRoot.dataset.oasisExecutiveViBound === '1') {
        return;
    }
    panelRoot.dataset.oasisExecutiveViBound = '1';
    selVi.addEventListener('change', function () {
        const rel = String(selVi.value || '').trim();
        if (!rel || typeof DashboardApp.fetchReportJsonPayload !== 'function') {
            DashboardApp.populateAssistantFindingSelectorsFromPayload(panelRoot, txt, { files: [] });
            return;
        }
        DashboardApp.fetchReportJsonPayload(rel)
            .then(function (payload) {
                if (!payload || typeof payload !== 'object') {
                    DashboardApp.populateAssistantFindingSelectorsFromPayload(panelRoot, txt, {
                        files: [],
                    });
                    return;
                }
                DashboardApp.populateAssistantFindingSelectorsFromPayload(panelRoot, txt, payload);
            })
            .catch(function () {
                DashboardApp.populateAssistantFindingSelectorsFromPayload(panelRoot, txt, { files: [] });
            });
    });
};

DashboardApp.mountReportAssistantPanel = function () {
    const cfg = window.__OASIS_DASHBOARD__ || {};
    if (!cfg.assistantEnabled) {
        return;
    }
    DashboardApp.ensureReportModalState();
    const rms = DashboardApp.reportModalState;
    const rawPath = rms.currentPath || '';
    if (!rawPath) {
        return;
    }
    const canonicalPath = DashboardApp.canonicalAssistantReportPath(rawPath);
    const execSummary = DashboardApp.isExecutiveSummaryPath(canonicalPath);
    if (rms.currentFormat !== 'json' && !execSummary) {
        return;
    }

    const wrapper = document.getElementById('report-modal-content');
    if (!wrapper || wrapper.querySelector('.oasis-assistant-panel')) {
        return;
    }

    const reportPath = canonicalPath;
    DashboardApp._assistantReportPath = reportPath;
    DashboardApp._assistantAggregateMode = !!execSummary;
    const showFindingSelectors = rms.currentFormat === 'json' && !execSummary;
    const showFindingRefBlock = showFindingSelectors || execSummary;

    const ui = DashboardApp.ASSISTANT_UI || {};
    const txt = function (key, fallback) {
        const v = ui[key];
        return typeof v === 'string' ? v : fallback;
    };

    const contextBadgeText = execSummary
        ? txt('contextExecutiveAggregate', 'Context: full scan (aggregate JSON)')
        : txt('contextSingleVuln', 'Context: single vulnerability report');
    const findingHiddenClass = showFindingRefBlock ? '' : ' oasis-assistant-finding-ref--hidden';
    const viRowHtml = execSummary
        ? `
                        <label class="oasis-assistant-finding-field"><span class="oasis-assistant-finding-key">${DashboardApp._escapeHtml(txt('findingVulnReportLabel', 'Vulnerability'))}</span>
                            <select id="oasis-assistant-vi" aria-label="${DashboardApp._escapeHtml(txt('ariaFindingVulnReport', 'Vulnerability report'))}"></select>
                        </label>`
        : '';

    const panel = document.createElement('div');
    panel.className = 'oasis-assistant-panel';
    panel.setAttribute('role', 'region');
    panel.setAttribute('aria-label', txt('panelSummary', 'Assistant'));
    panel.innerHTML = `
            <div class="oasis-assistant-meta-bar">
                <span class="oasis-assistant-context-badge" id="oasis-assistant-context-badge">${DashboardApp._escapeHtml(contextBadgeText)}</span>
                <label class="oasis-assistant-model-field">${DashboardApp._escapeHtml(txt('chatModelLabel', 'Chat model'))}
                    <select id="oasis-assistant-chat-model" aria-label="${DashboardApp._escapeHtml(txt('chatModelLabel', 'Chat model'))}"></select>
                </label>
                <span class="oasis-assistant-budget-hint" id="oasis-assistant-budget-hint" aria-live="polite"></span>
            </div>
            <div class="oasis-assistant-session-bar">
                <label class="oasis-assistant-session-label">${DashboardApp._escapeHtml(txt('sessionLabel', 'Session'))}
                    <select id="oasis-assistant-session-select" aria-label="${DashboardApp._escapeHtml(txt('sessionAriaLabel', 'Chat session'))}"></select>
                </label>
                <button type="button" class="btn btn-secondary btn-sm" id="oasis-assistant-new">${DashboardApp._escapeHtml(txt('newChat', 'New chat'))}</button>
                <button type="button" class="btn btn-secondary btn-sm" id="oasis-assistant-delete-one">${DashboardApp._escapeHtml(txt('deleteOne', 'Delete'))}</button>
                <button type="button" class="btn btn-secondary btn-sm" id="oasis-assistant-delete-all">${DashboardApp._escapeHtml(txt('deleteAll', 'Clear all'))}</button>
            </div>
            <div class="oasis-assistant-controls">
                <label class="oasis-assistant-rag-label">
                    <input type="checkbox" id="oasis-assistant-rag" ${cfg.assistantRagDefault !== false ? 'checked' : ''}/>
                    ${DashboardApp._escapeHtml(txt('ragLabel', 'RAG'))}
                </label>
                <label class="oasis-assistant-expand-label">
                    <input type="checkbox" id="oasis-assistant-expand"/>
                    ${DashboardApp._escapeHtml(txt('expandLabel', 'Expand'))}
                </label>
                <div class="oasis-assistant-finding-ref${findingHiddenClass}">
                    <span class="oasis-assistant-finding-ref-intro">${DashboardApp._escapeHtml(txt('findingRefIntro', ''))}</span>
                    <div class="oasis-assistant-finding-selects">
                        ${viRowHtml}
                        <label class="oasis-assistant-finding-field"><span class="oasis-assistant-finding-key">${DashboardApp._escapeHtml(txt('findingFileLabel', 'File'))}</span>
                            <select id="oasis-assistant-fi" aria-label="${DashboardApp._escapeHtml(txt('ariaFindingFile', 'File'))}"></select>
                        </label>
                        <label class="oasis-assistant-finding-field"><span class="oasis-assistant-finding-key">${DashboardApp._escapeHtml(txt('findingChunkLabel', 'Chunk'))}</span>
                            <select id="oasis-assistant-ci" aria-label="${DashboardApp._escapeHtml(txt('ariaFindingChunk', 'Chunk'))}"></select>
                        </label>
                        <label class="oasis-assistant-finding-field"><span class="oasis-assistant-finding-key">${DashboardApp._escapeHtml(txt('findingFindingLabel', 'Finding'))}</span>
                            <select id="oasis-assistant-gi" aria-label="${DashboardApp._escapeHtml(txt('ariaFindingFinding', 'Finding'))}"></select>
                        </label>
                    </div>
                </div>
                <div class="oasis-assistant-chips">
                    <button type="button" class="btn btn-secondary oasis-chip" data-q="${DashboardApp._escapeHtml(txt('chipQueryFalsePositive', ''))}">${DashboardApp._escapeHtml(txt('chipFalsePositive', ''))}</button>
                    <button type="button" class="btn btn-secondary oasis-chip" data-q="${DashboardApp._escapeHtml(txt('chipQueryNextChecks', ''))}">${DashboardApp._escapeHtml(txt('chipNextChecks', ''))}</button>
                    <button type="button" class="btn btn-secondary oasis-chip" data-q="${DashboardApp._escapeHtml(txt('chipQueryPreconditions', ''))}">${DashboardApp._escapeHtml(txt('chipPreconditions', ''))}</button>
                    <button type="button" class="btn btn-secondary oasis-chip" data-q="${DashboardApp._escapeHtml(txt('chipQueryExploit', ''))}">${DashboardApp._escapeHtml(txt('chipExploit', 'Exploit'))}</button>
                    <button type="button" class="btn btn-secondary oasis-chip" data-q="${DashboardApp._escapeHtml(txt('chipQueryHttpRequest', ''))}">${DashboardApp._escapeHtml(txt('chipHttpRequest', 'HTTP request'))}</button>
                </div>
                <textarea id="oasis-assistant-input" class="oasis-assistant-input" rows="3" placeholder="${DashboardApp._escapeHtml(txt('inputPlaceholder', ''))}"></textarea>
                <button type="button" class="btn btn-primary" id="oasis-assistant-send">${DashboardApp._escapeHtml(txt('send', 'Send'))}</button>
            </div>
            <div class="oasis-assistant-convo-row">
                <aside class="oasis-assistant-index-column" aria-label="${DashboardApp._escapeHtml(txt('ariaQuestionsIndex', 'Question index'))}">
                    <div class="oasis-assistant-index-heading">${DashboardApp._escapeHtml(txt('questionsIndexTitle', 'Questions'))}</div>
                    <nav id="oasis-assistant-q-index" class="oasis-assistant-q-index-nav"></nav>
                </aside>
                <div class="oasis-assistant-log-column">
                    <div id="oasis-assistant-log" class="oasis-assistant-log" aria-live="polite"></div>
                </div>
            </div>
    `;

    let mountPoint = document.getElementById('oasis-assistant-mount');
    if (!mountPoint) {
        const mountParent =
            wrapper.querySelector('.executive-preview') ||
            wrapper.querySelector('.html-content-container') ||
            wrapper;
        const section = document.createElement('section');
        section.id = 'assistant';
        section.className = 'report-assistant-section oasis-assistant-synthetic-wrap';

        const titleEl = document.createElement('h2');
        titleEl.textContent = txt('panelSummary', 'Assistant (triage / codebase)');

        const leadEl = document.createElement('p');
        leadEl.className = 'report-assistant-lead';
        leadEl.textContent = txt(
            'assistantLeadExecutive',
            'In the OASIS dashboard (executive summary preview), use the chat below for scan-wide triage: severity patterns, cross-report themes, and remediation priorities. Optional vulnerability and finding scope narrows context when needed.'
        );

        mountPoint = document.createElement('div');
        mountPoint.id = 'oasis-assistant-mount';
        mountPoint.className = 'oasis-assistant-mount';

        section.appendChild(titleEl);
        section.appendChild(leadEl);
        section.appendChild(mountPoint);
        mountParent.appendChild(section);
    }
    mountPoint.appendChild(panel);

    /* report_template.html puts .report-footer before the injected assistant in DOM order; relocate below the panel. */
    wrapper.querySelectorAll('footer.report-footer').forEach(function (footer) {
        if (!footer.parentNode) {
            return;
        }
        footer.parentNode.removeChild(footer);
        wrapper.appendChild(footer);
    });

    if (showFindingSelectors) {
        DashboardApp.wireAssistantFindingSelectors(panel, txt, reportPath);
    }
    if (execSummary) {
        DashboardApp.wireAssistantExecutiveFindingSelectors(panel, txt, rawPath);
    }

    const chatModelLsKey = DashboardApp._assistantChatModelStorageKey(reportPath);
    const chatModelSelect = panel.querySelector('#oasis-assistant-chat-model');
    const budgetHintEl = panel.querySelector('#oasis-assistant-budget-hint');

    const formatBudgetHint = function (chars) {
        if (typeof chars !== 'number' || !Number.isFinite(chars) || chars <= 0) {
            return '';
        }
        let n = chars;
        let suffix = '';
        if (n >= 1000) {
            suffix = 'K';
            n = Math.round(n / 1000);
        }
        return `${txt('budgetHintPrefix', 'System prompt budget ~')}${n}${suffix} chars`;
    };

    if (chatModelSelect) {
        chatModelSelect.addEventListener('change', function () {
            try {
                window.localStorage.setItem(chatModelLsKey, chatModelSelect.value || '');
            } catch (e) {
                /* ignore */
            }
        });
    }

    const logEl = panel.querySelector('#oasis-assistant-log');
    const wireMdCodeCopy = function () {
        DashboardApp.wireMarkdownCodeCopyButtons(logEl, {
            copyCode: txt('copyCode', 'Copy'),
            copiedCode: txt('copiedCode', 'Copied'),
        });
    };
    const inputEl = panel.querySelector('#oasis-assistant-input');
    const sendBtn = panel.querySelector('#oasis-assistant-send');
    const sessionSelect = panel.querySelector('#oasis-assistant-session-select');
    const newBtn = panel.querySelector('#oasis-assistant-new');
    const delOneBtn = panel.querySelector('#oasis-assistant-delete-one');
    const delAllBtn = panel.querySelector('#oasis-assistant-delete-all');

    let userQuestionSeq = 0;

    const rebuildQuestionIndex = function () {
        const nav = panel.querySelector('#oasis-assistant-q-index');
        if (!nav || !logEl) {
            return;
        }
        DashboardApp._clearElement(nav);
        let qn = 0;
        DashboardApp._assistantConversation.forEach(function (m) {
            if (m.role !== 'user') {
                return;
            }
            qn += 1;
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'oasis-assistant-index-btn';
            const raw = typeof m.content === 'string' ? m.content : '';
            const snippetMd = DashboardApp._truncateAssistantLabel(raw, 72);
            const numHtml =
                '<span class="oasis-assistant-index-num">' +
                DashboardApp._escapeHtml(String(qn)) +
                '.</span>';
            btn.innerHTML =
                numHtml +
                DashboardApp.renderUserMessageMarkdownHtml(snippetMd, { variant: 'index' });
            btn.setAttribute(
                'aria-label',
                txt('jumpToQuestion', 'Jump to question') +
                    ' ' +
                    qn +
                    ': ' +
                    snippetMd.replace(/\s+/g, ' ').trim()
            );
            (function (idNum) {
                btn.addEventListener('click', function () {
                    const target = document.getElementById('oasis-assistant-q-' + idNum);
                    if (target && logEl) {
                        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        target.classList.add('oasis-assistant-msg--highlight');
                        window.setTimeout(function () {
                            target.classList.remove('oasis-assistant-msg--highlight');
                        }, 1400);
                    }
                });
            })(qn);
            nav.appendChild(btn);
        });
    };

    const appendUserMsg = function (text) {
        userQuestionSeq += 1;
        const row = document.createElement('div');
        row.className = 'oasis-assistant-msg oasis-assistant-msg--user';
        row.id = 'oasis-assistant-q-' + userQuestionSeq;
        const hd = document.createElement('div');
        hd.className = 'oasis-assistant-msg-hd';
        hd.textContent = txt('msgLabelUser', 'You');
        const body = document.createElement('div');
        body.className = 'oasis-assistant-msg-body oasis-assistant-msg-body--rich';
        body.innerHTML = DashboardApp.renderUserMessageMarkdownHtml(text);
        row.appendChild(hd);
        row.appendChild(body);
        logEl.appendChild(row);
        logEl.scrollTop = logEl.scrollHeight;
        wireMdCodeCopy();
    };

    const appendAssistantMsg = function (payload) {
        const row = document.createElement('div');
        row.className = 'oasis-assistant-msg oasis-assistant-msg--assistant';
        const hd = document.createElement('div');
        hd.className = 'oasis-assistant-msg-hd';
        hd.textContent = txt('msgLabelAssistant', 'Assistant');
        const body = document.createElement('div');
        body.className = 'oasis-assistant-msg-body oasis-assistant-msg-body--rich';
        body.innerHTML = DashboardApp.renderAssistantMessageHtml(payload);
        row.appendChild(hd);
        row.appendChild(body);
        logEl.appendChild(row);
        logEl.scrollTop = logEl.scrollHeight;
        wireMdCodeCopy();
    };

    const renderLog = function () {
        userQuestionSeq = 0;
        DashboardApp._clearElement(logEl);
        DashboardApp._assistantConversation.forEach(function (m) {
            if (m.role === 'user') {
                appendUserMsg(typeof m.content === 'string' ? m.content : '');
            } else if (m.role === 'assistant') {
                appendAssistantMsg(m);
            }
        });
        rebuildQuestionIndex();
    };

    const populateSessionSelect = function (rows, selectedId) {
        DashboardApp._clearElement(sessionSelect);
        const optPlaceholder = document.createElement('option');
        optPlaceholder.value = '';
        optPlaceholder.textContent = rows.length
            ? txt('sessionSelectPlaceholder', '— select —')
            : txt('sessionSelectEmpty', '(no saved chats)');
        sessionSelect.appendChild(optPlaceholder);
        rows.forEach(function (row) {
            const opt = document.createElement('option');
            opt.value = row.session_id;
            const updated = row.updated_at || '';
            const cnt = typeof row.message_count === 'number' ? row.message_count : '';
            opt.textContent = (updated ? updated + ' · ' : '') + cnt + txt('sessionMetaSuffix', ' msg');
            sessionSelect.appendChild(opt);
        });
        if (selectedId) {
            sessionSelect.value = selectedId;
        }
    };

    const refreshSessionList = function (selectedId) {
        return DashboardApp.fetchAssistantSessions(reportPath, 30)
            .then(function (rows) {
                populateSessionSelect(rows, selectedId || DashboardApp._assistantSessionId);
            })
            .catch(function () {
                populateSessionSelect([], '');
            });
    };

    let cachedSortedChatModels = [];
    let reportPreferredModelStr = '';

    const startNewChat = function () {
        DashboardApp._assistantConversation = [];
        DashboardApp._assistantSessionId = DashboardApp._newAssistantSessionId();
        userQuestionSeq = 0;
        DashboardApp._clearElement(logEl);
        rebuildQuestionIndex();
        if (chatModelSelect && cachedSortedChatModels.length) {
            applyAssistantChatModelSeed(cachedSortedChatModels, reportPreferredModelStr);
        }
        refreshSessionList(DashboardApp._assistantSessionId);
    };

    const applyAssistantChatModelSeed = function (sortedNames, seedPreferred) {
        if (!chatModelSelect) {
            return;
        }
        let lsScoped = '';
        let lsLegacy = '';
        try {
            lsScoped = window.localStorage.getItem(chatModelLsKey) || '';
        } catch (e) {
            lsScoped = '';
        }
        try {
            lsLegacy = window.localStorage.getItem('oasis_assistant_chat_model') || '';
        } catch (e) {
            lsLegacy = '';
        }
        const seed = typeof seedPreferred === 'string' ? seedPreferred.trim() : '';
        let pick = '';
        if (seed && sortedNames.indexOf(seed) >= 0) {
            pick = seed;
        } else if (lsScoped && sortedNames.indexOf(lsScoped) >= 0) {
            pick = lsScoped;
        } else if (lsLegacy && sortedNames.indexOf(lsLegacy) >= 0) {
            pick = lsLegacy;
        } else if (sortedNames.length > 0) {
            pick = sortedNames[0];
        }
        if (pick) {
            chatModelSelect.value = pick;
        }
    };

    const syncChatModelFromSessionDoc = function (doc) {
        if (!chatModelSelect || !doc || typeof doc !== 'object') {
            return;
        }
        const m = typeof doc.model === 'string' ? doc.model.trim() : '';
        if (!m) {
            return;
        }
        const opts = chatModelSelect.querySelectorAll('option');
        for (let i = 0; i < opts.length; i++) {
            if (opts[i].value === m) {
                chatModelSelect.value = m;
                return;
            }
        }
    };

    const loadSessionById = function (sessionId) {
        if (!sessionId) {
            startNewChat();
            return Promise.resolve();
        }
        return DashboardApp.fetchAssistantSession(reportPath, sessionId)
            .then(function (doc) {
                const raw = Array.isArray(doc.messages) ? doc.messages : [];
                const trimmed = DashboardApp._trimAssistantMessages(raw);
                DashboardApp._assistantConversation = trimmed.map(function (m) {
                    if (!m || typeof m !== 'object') {
                        return { role: 'user', content: '', at: '' };
                    }
                    const base = {
                        role: m.role,
                        content: typeof m.content === 'string' ? m.content : '',
                        at: typeof m.at === 'string' ? m.at : '',
                    };
                    if (m.role === 'assistant') {
                        if (typeof m.visible_markdown === 'string') {
                            base.visible_markdown = m.visible_markdown;
                        }
                        if (Array.isArray(m.thought_segments)) {
                            base.thought_segments = m.thought_segments;
                        }
                    }
                    return base;
                });
                DashboardApp._assistantSessionId = doc.session_id || sessionId;
                syncChatModelFromSessionDoc(doc);
                renderLog();
            })
            .catch(function () {
                startNewChat();
            });
    };

    sessionSelect.addEventListener('change', function () {
        const v = sessionSelect.value;
        if (!v) {
            return;
        }
        loadSessionById(v);
    });

    newBtn.addEventListener('click', function () {
        startNewChat();
    });

    delOneBtn.addEventListener('click', function () {
        if (!DashboardApp._assistantSessionId) {
            return;
        }
        if (!window.confirm(txt('confirmDeleteSession', 'Delete this chat session?'))) {
            return;
        }
        DashboardApp.deleteAssistantSession(reportPath, DashboardApp._assistantSessionId)
            .then(function () {
                startNewChat();
                return refreshSessionList('');
            })
            .catch(function (err) {
                appendAssistantMsg({
                    message: 'Error: ' + DashboardApp._errorMessage(err),
                });
            });
    });

    delAllBtn.addEventListener('click', function () {
        if (!window.confirm(txt('confirmDeleteAll', 'Delete all chat sessions?'))) {
            return;
        }
        DashboardApp.deleteAllAssistantSessions(reportPath)
            .then(function () {
                startNewChat();
                return refreshSessionList('');
            })
            .catch(function (err) {
                appendAssistantMsg({
                    message: 'Error: ' + DashboardApp._errorMessage(err),
                });
            });
    });

    const gatherFindingIndices = function (panelRoot) {
        if (!panelRoot) {
            return {
                finding_scope_report_path: '',
                file_index: null,
                chunk_index: null,
                finding_index: null,
            };
        }
        const vi = panelRoot.querySelector('#oasis-assistant-vi');
        const fi = panelRoot.querySelector('#oasis-assistant-fi');
        const ci = panelRoot.querySelector('#oasis-assistant-ci');
        const gi = panelRoot.querySelector('#oasis-assistant-gi');
        const num = function (el) {
            const v = el && el.value;
            if (v === '' || v === undefined || v === null) {
                return null;
            }
            const n = Number(v);
            return Number.isFinite(n) ? n : null;
        };
        const scopeRel =
            vi && typeof vi.value === 'string' && vi.value.trim() ? vi.value.trim() : '';
        return {
            finding_scope_report_path: scopeRel,
            file_index: num(fi),
            chunk_index: num(ci),
            finding_index: num(gi),
        };
    };

    const sendQuestion = function (text) {
        const q = String(text || '').trim();
        if (!q) {
            return;
        }
        if (!DashboardApp._assistantSessionId) {
            DashboardApp._assistantSessionId = DashboardApp._newAssistantSessionId();
        }
        const nowIso = new Date().toISOString();
        appendUserMsg(q);
        DashboardApp._assistantConversation.push({ role: 'user', content: q, at: nowIso });
        DashboardApp._assistantConversation = DashboardApp._trimAssistantMessages(
            DashboardApp._assistantConversation
        );
        rebuildQuestionIndex();

        const ragEl = panel.querySelector('#oasis-assistant-rag');
        const expandEl = panel.querySelector('#oasis-assistant-expand');
        const indices = gatherFindingIndices(panel);
        const payload = {
            messages: DashboardApp._assistantMessagesForApi(),
            report_path: reportPath,
            session_id: DashboardApp._assistantSessionId,
            rag_expand_project: !!(expandEl && expandEl.checked),
        };
        const cm =
            chatModelSelect && chatModelSelect.value ? String(chatModelSelect.value).trim() : '';
        if (cm) {
            payload.model = cm;
        }
        if (execSummary) {
            payload.aggregate_model_json = true;
        }
        try {
            const labelsRaw = localStorage.getItem(`oasis_labels_${reportPath}`);
            if (labelsRaw) {
                payload.user_finding_labels = labelsRaw;
            }
        } catch (e) {
            /* ignore */
        }
        if (ragEl && !ragEl.checked) {
            payload.rag_disabled = true;
        }
        if (showFindingSelectors || execSummary) {
            Object.assign(payload, indices);
            if (!indices.finding_scope_report_path) {
                delete payload.finding_scope_report_path;
            }
        }

        sendBtn.disabled = true;
        DashboardApp.postAssistantChat(payload)
            .then(function (data) {
                if (budgetHintEl) {
                    budgetHintEl.textContent = formatBudgetHint(data.system_budget_chars);
                }
                const answer = typeof data.message === 'string' ? data.message : '';
                const replyPayload = {
                    message: answer,
                    visible_markdown: data.visible_markdown,
                    thought_segments: data.thought_segments,
                };
                appendAssistantMsg(replyPayload);
                const ts = new Date().toISOString();
                DashboardApp._assistantConversation.push({
                    role: 'assistant',
                    content: answer,
                    at: ts,
                    visible_markdown:
                        typeof data.visible_markdown === 'string' ? data.visible_markdown : undefined,
                    thought_segments: Array.isArray(data.thought_segments) ? data.thought_segments : undefined,
                });
                DashboardApp._assistantConversation = DashboardApp._trimAssistantMessages(
                    DashboardApp._assistantConversation
                );
                if (typeof data.session_id === 'string' && data.session_id) {
                    DashboardApp._assistantSessionId = data.session_id;
                }
                return refreshSessionList(DashboardApp._assistantSessionId);
            })
            .catch(function (err) {
                const msg = DashboardApp._errorMessage(err);
                appendAssistantMsg({ message: 'Error: ' + msg });
            })
            .finally(function () {
                sendBtn.disabled = false;
                inputEl.value = '';
            });
    };

    sendBtn.addEventListener('click', function () {
        sendQuestion(inputEl.value);
    });

    panel.querySelectorAll('.oasis-chip').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const q = btn.getAttribute('data-q') || '';
            inputEl.value = q;
            sendQuestion(q);
        });
    });

    const reportModelNamePromise =
        typeof DashboardApp.fetchReportJsonPayload === 'function'
            ? DashboardApp.fetchReportJsonPayload(reportPath)
                  .then(function (payload) {
                      return DashboardApp.preferredChatModelFromReportPayload(payload);
                  })
                  .catch(function () {
                      return '';
                  })
            : Promise.resolve('');

    Promise.all([
        DashboardApp.fetchAssistantChatModels().catch(function () {
            return [];
        }),
        reportModelNamePromise,
        DashboardApp.fetchAssistantSessions(reportPath, 30).catch(function () {
            return [];
        }),
    ])
        .then(function (triple) {
            const models = Array.isArray(triple[0]) ? triple[0] : [];
            const reportMn = typeof triple[1] === 'string' ? triple[1] : '';
            const rows = Array.isArray(triple[2]) ? triple[2] : [];

            if (!chatModelSelect) {
                return Promise.resolve();
            }

            cachedSortedChatModels = [];
            reportPreferredModelStr = reportMn;

            DashboardApp._clearElement(chatModelSelect);
            const sorted = models.slice().sort(function (a, b) {
                return String(a).localeCompare(String(b));
            });
            sorted.forEach(function (name) {
                const opt = document.createElement('option');
                opt.value = name;
                opt.textContent = name;
                chatModelSelect.appendChild(opt);
            });
            cachedSortedChatModels = sorted.slice();
            if (sorted.length === 0) {
                const optEmpty = document.createElement('option');
                optEmpty.value = '';
                optEmpty.textContent = txt('chatModelsUnavailable', '(models unavailable)');
                chatModelSelect.appendChild(optEmpty);
            }

            let seed = '';
            if (reportMn) {
                seed = reportMn;
            } else if (rows.length && rows[0].model && String(rows[0].model).trim()) {
                seed = String(rows[0].model).trim();
            }
            applyAssistantChatModelSeed(sorted, seed);

            if (rows.length > 0) {
                const firstId = rows[0].session_id;
                populateSessionSelect(rows, firstId);
                return loadSessionById(firstId).then(function () {
                    return refreshSessionList(DashboardApp._assistantSessionId);
                });
            }
            populateSessionSelect([], '');
            startNewChat();
            return refreshSessionList('');
        })
        .catch(function () {
            if (chatModelSelect) {
                DashboardApp._clearElement(chatModelSelect);
                const opt = document.createElement('option');
                opt.value = '';
                opt.textContent = txt('chatModelsUnavailable', '(models unavailable)');
                chatModelSelect.appendChild(opt);
            }
            startNewChat();
            refreshSessionList('');
        });
};
