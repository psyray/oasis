// Dashboard report assistant (LLM triage via /api/assistant/chat).
DashboardApp._assistantConversation = [];
DashboardApp._assistantSessionId = '';
DashboardApp._assistantReportPath = '';

DashboardApp.resetAssistantConversation = function () {
    DashboardApp._assistantConversation = [];
    DashboardApp._assistantSessionId = '';
};

/**
 * Render the ``AssistantInvestigationResult`` payload returned by
 * ``/api/assistant/investigate`` inside a plain container. Layout is
 * intentionally lightweight (dl + lists) so it composes cleanly in both
 * the assistant panel and any future modal/aside embedding.
 */
DashboardApp._validateStatusTone = function (status) {
    switch (String(status || '').toLowerCase()) {
        case 'confirmed_exploitable':
            return 'danger';
        case 'likely_exploitable':
        case 'partial_mitigation':
            return 'warn';
        case 'fully_mitigated':
            return 'ok';
        case 'unreachable':
        case 'insufficient_signal':
            return 'muted';
        case 'error':
            return 'danger';
        default:
            return 'muted';
    }
};

DashboardApp._validateShortenPath = function (value, keep) {
    const s = value == null ? '' : String(value);
    const k = typeof keep === 'number' && keep > 0 ? keep : 3;
    const parts = s ? s.split('/') : [];
    if (parts.length <= k + 1) {
        return s;
    }
    return '…/' + parts.slice(-k).join('/');
};

/** Matches ``finding_validation_storage_key`` in ``assistant_persistence.py`` (sorted JSON keys). */
DashboardApp.findingValidationStorageKey = function (indices) {
    if (!indices || typeof indices !== 'object') {
        return null;
    }
    const s = typeof indices.finding_scope_report_path === 'string' ? indices.finding_scope_report_path.trim() : '';
    const fi = indices.file_index;
    const ci = indices.chunk_index;
    const gi = indices.finding_index;
    if (!Number.isFinite(fi) || !Number.isFinite(ci) || !Number.isFinite(gi)) {
        return null;
    }
    if (fi < 0 || ci < 0 || gi < 0) {
        return null;
    }
    return JSON.stringify({ ci: ci, fi: fi, gi: gi, s: s });
};

DashboardApp._gatherAssistantFindingIndices = function (panelRoot) {
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

/** Human-readable pills for the selected finding (Validate row); uses dashboard charter pills. */
DashboardApp.updateAssistantValidateTargetSummary = function (panel, txt) {
    const el = panel && panel.querySelector('#oasis-assistant-validate-target');
    if (!el) {
        return;
    }
    const label = function (key, fallback) {
        return typeof txt === 'function' ? txt(key, fallback) : fallback;
    };
    DashboardApp._clearElement(el);
    const indices = DashboardApp._gatherAssistantFindingIndices(panel);
    const files = Array.isArray(panel._oasisAssistantFiles) ? panel._oasisAssistantFiles : [];
    const wrap = document.createElement('div');
    wrap.className = 'oasis-assistant-validate-target-inner';

    const addPill = function (text, titleAttr) {
        const sp = document.createElement('span');
        sp.className = 'oasis-assistant-validate-vuln oasis-assistant-validate-target-pill';
        sp.textContent = text;
        if (titleAttr) {
            sp.title = titleAttr;
        }
        wrap.appendChild(sp);
    };

    const scopeRel = indices.finding_scope_report_path || '';
    if (scopeRel) {
        addPill(
            label('validateTargetScopeLabel', 'Report') +
                ': ' +
                DashboardApp._truncateAssistantLabel(scopeRel, 72),
            scopeRel
        );
    }

    const fi = indices.file_index;
    const ci = indices.chunk_index;
    const gi = indices.finding_index;
    if (
        !Number.isFinite(fi) ||
        fi < 0 ||
        fi >= files.length ||
        !Number.isFinite(ci) ||
        !Number.isFinite(gi)
    ) {
        const hint = document.createElement('span');
        hint.className = 'oasis-assistant-validate-target-hint';
        hint.textContent = label(
            'validateTargetIncomplete',
            'Select file, chunk, and finding for validation scope.'
        );
        el.appendChild(hint);
        return;
    }
    const fileEntry = files[fi] || {};
    const fp =
        fileEntry && typeof fileEntry.file_path === 'string' && fileEntry.file_path.trim()
            ? fileEntry.file_path.trim()
            : '(' + fi + ')';
    addPill(
        label('findingFileLabel', 'File') + ': ' + DashboardApp._truncateAssistantLabel(fp, 72),
        fp
    );
    const chunks = Array.isArray(fileEntry.chunk_analyses) ? fileEntry.chunk_analyses : [];
    const chunk = ci >= 0 && ci < chunks.length ? chunks[ci] : null;
    let chunkText = label('findingChunkLabel', 'Chunk') + ' ' + (ci + 1);
    if (chunk && chunk.start_line != null && chunk.end_line != null) {
        chunkText += ' (lines ' + chunk.start_line + '–' + chunk.end_line + ')';
    }
    addPill(DashboardApp._truncateAssistantLabel(chunkText, 96), chunkText);
    const findings = chunk && Array.isArray(chunk.findings) ? chunk.findings : [];
    const fd = gi >= 0 && gi < findings.length ? findings[gi] : null;
    const ft =
        fd && typeof fd.title === 'string' && fd.title.trim()
            ? fd.title.trim()
            : label('findingFindingLabel', 'Finding') + ' ' + (gi + 1);
    addPill(DashboardApp._truncateAssistantLabel(ft, 88), ft);
    el.appendChild(wrap);
};

DashboardApp.refreshAssistantVerdictPanelFromSession = function (panel, txt) {
    const reportPath = DashboardApp._assistantReportPath || '';
    const sid = DashboardApp._assistantSessionId;
    const chatModelSelect = panel && panel.querySelector('#oasis-assistant-chat-model');
    const cm = chatModelSelect && chatModelSelect.value ? String(chatModelSelect.value).trim() : '';
    const validatePanel = panel && panel.querySelector('#oasis-assistant-validate-panel');
    if (!panel || !reportPath || !sid || !cm || !validatePanel) {
        return Promise.resolve();
    }
    const fk = DashboardApp.findingValidationStorageKey(DashboardApp._gatherAssistantFindingIndices(panel));
    if (!fk) {
        validatePanel.hidden = true;
        DashboardApp._clearElement(validatePanel);
        return Promise.resolve();
    }
    return DashboardApp.fetchAssistantSession(reportPath, sid)
        .then(function (doc) {
            if (!doc || typeof doc !== 'object') {
                return;
            }
            const branches =
                doc.model_branches && typeof doc.model_branches === 'object' ? doc.model_branches : {};
            const br = branches[cm];
            const rawMap = br && br.finding_validations;
            const fv =
                rawMap && typeof rawMap === 'object' && typeof rawMap[fk] === 'object'
                    ? rawMap[fk]
                    : null;
            if (fv) {
                validatePanel.hidden = false;
                DashboardApp.renderAssistantVerdictPanel(validatePanel, fv, txt);
            } else {
                validatePanel.hidden = true;
                DashboardApp._clearElement(validatePanel);
            }
        })
        .catch(function () {
            /* ignore */
        });
};

/**
 * Render the ``AssistantInvestigationResult`` payload returned by
 * ``/api/assistant/investigate`` with the dashboard charter. Layout is
 * compact (verdict header + scope card + collapsible evidence sections)
 * and the entry-points list is rendered inside a bounded, scrollable
 * container so every hit stays reachable regardless of volume.
 */
DashboardApp.renderAssistantVerdictPanel = function (container, result, txt) {
    if (!container) {
        return;
    }
    const esc = DashboardApp._escapeHtml || function (s) {
        return String(s == null ? '' : s);
    };
    const label = function (key, fallback) {
        return typeof txt === 'function' ? txt(key, fallback) : fallback;
    };
    const shortPath = DashboardApp._validateShortenPath;
    while (container.firstChild) {
        container.removeChild(container.firstChild);
    }
    if (!result || typeof result !== 'object') {
        container.textContent = label('validateEmpty', 'No evidence recorded.');
        return;
    }
    container.classList.add('oasis-assistant-validate-panel');

    const tone = DashboardApp._validateStatusTone(result.status);
    // Drop previous tone classes if the panel is being re-rendered.
    ['danger', 'warn', 'ok', 'muted'].forEach(function (t) {
        container.classList.remove('oasis-assistant-validate-panel--' + t);
    });
    container.classList.add('oasis-assistant-validate-panel--' + tone);
    const confidencePct = typeof result.confidence === 'number'
        ? Math.max(0, Math.min(100, Math.round(result.confidence * 100)))
        : null;
    const statusText = String(result.status || '—').replace(/_/g, ' ');
    const familyText = String(result.family || '—');
    const vulnName =
        (result.scope && result.scope.vulnerability_name) || result.vulnerability_name || '';

    // Header: title + status badge + confidence gauge — single compact row.
    const head = document.createElement('div');
    head.className = 'oasis-assistant-validate-head oasis-assistant-validate-head--' + tone;
    const headLeft = document.createElement('div');
    headLeft.className = 'oasis-assistant-validate-head-left';
    const title = document.createElement('span');
    title.className = 'oasis-assistant-validate-title';
    title.textContent = label('validateHeader', 'Finding validation');
    headLeft.appendChild(title);
    if (vulnName) {
        const vname = document.createElement('span');
        vname.className = 'oasis-assistant-validate-vuln';
        vname.textContent = vulnName;
        headLeft.appendChild(vname);
    }
    head.appendChild(headLeft);

    const headRight = document.createElement('div');
    headRight.className = 'oasis-assistant-validate-head-right';
    const statusBadge = document.createElement('span');
    statusBadge.className = 'oasis-assistant-validate-status oasis-assistant-validate-status--' + tone;
    statusBadge.textContent = statusText;
    headRight.appendChild(statusBadge);
    const familyPill = document.createElement('span');
    familyPill.className = 'oasis-assistant-validate-family';
    familyPill.textContent = familyText;
    headRight.appendChild(familyPill);
    head.appendChild(headRight);
    container.appendChild(head);

    if (confidencePct !== null) {
        const gauge = document.createElement('div');
        gauge.className = 'oasis-assistant-validate-gauge oasis-assistant-validate-gauge--' + tone;
        const gLabel = document.createElement('span');
        gLabel.className = 'oasis-assistant-validate-gauge-label';
        gLabel.textContent = label('validateConfidenceLabel', 'Confidence');
        const gTrack = document.createElement('span');
        gTrack.className = 'oasis-assistant-validate-gauge-track';
        const gFill = document.createElement('span');
        gFill.className = 'oasis-assistant-validate-gauge-fill';
        gFill.style.width = confidencePct + '%';
        gTrack.appendChild(gFill);
        const gValue = document.createElement('span');
        gValue.className = 'oasis-assistant-validate-gauge-value';
        gValue.textContent = confidencePct + '%';
        gauge.appendChild(gLabel);
        gauge.appendChild(gTrack);
        gauge.appendChild(gValue);
        container.appendChild(gauge);
    }

    const summaryText = typeof result.summary === 'string' ? result.summary.trim() : '';
    if (summaryText) {
        const narrative = document.createElement('p');
        narrative.className = 'oasis-assistant-validate-narrative';
        narrative.textContent = summaryText;
        container.appendChild(narrative);
    }

    const llmMd =
        result.narrative_markdown && String(result.narrative_markdown).trim()
            ? String(result.narrative_markdown).trim()
            : '';
    const synthesisModelText = typeof result.synthesis_model === 'string'
        ? String(result.synthesis_model).trim()
        : '';
    const synthesisErrorText =
        result.synthesis_error && String(result.synthesis_error).trim()
            ? String(result.synthesis_error).trim()
            : '';
    if (llmMd) {
        const llmHead = document.createElement('div');
        llmHead.className = 'oasis-assistant-validate-llm-head';
        const llmTitle = document.createElement('span');
        llmTitle.className = 'oasis-assistant-validate-llm-title';
        llmTitle.textContent = label('validateLlmNarrativeTitle', 'LLM narrative');
        llmHead.appendChild(llmTitle);
        if (synthesisModelText) {
            const llmModel = document.createElement('span');
            llmModel.className = 'oasis-assistant-validate-llm-model';
            llmModel.textContent = synthesisModelText;
            llmHead.appendChild(llmModel);
        }
        container.appendChild(llmHead);
        const llmBody = document.createElement('div');
        llmBody.className = 'oasis-assistant-validate-llm-body oasis-assistant-md';
        let mdHtml = '';
        if (typeof DashboardApp.convertMarkdownToHtml === 'function') {
            mdHtml = DashboardApp.convertMarkdownToHtml(llmMd);
        } else {
            mdHtml = '<p>' + esc(llmMd) + '</p>';
        }
        llmBody.innerHTML =
            typeof DashboardApp._sanitizeHtml === 'function'
                ? DashboardApp._sanitizeHtml(mdHtml)
                : mdHtml;
        container.appendChild(llmBody);
        if (typeof DashboardApp.wireMarkdownCodeCopyButtons === 'function') {
            DashboardApp.wireMarkdownCodeCopyButtons(llmBody, {
                copyCode: label('assistantCopyCode', 'Copy'),
                copiedCode: label('assistantCopiedCode', 'Copied'),
            });
        }
    }
    if (!llmMd && synthesisErrorText) {
        const synErr = document.createElement('p');
        synErr.className = 'oasis-assistant-validate-synthesis-error';
        synErr.textContent =
            label('validateSynthesisErrorPrefix', 'Narrative synthesis: ') +
            synthesisErrorText;
        container.appendChild(synErr);
    }

    // Scope card — compact mono-space with truncation hint for long paths.
    if (result.scope && typeof result.scope === 'object') {
        const scope = document.createElement('div');
        scope.className = 'oasis-assistant-validate-scope';
        const scopeRows = [
            {
                key: 'scanroot',
                label: label('validateScopeRootLabel', 'Scan root'),
                full: result.scope.scan_root || '',
                short: shortPath(result.scope.scan_root, 3),
                mono: true,
            },
            {
                key: 'sink',
                label: label('validateScopeSinkLabel', 'Sink'),
                full: result.scope.sink_file
                    ? result.scope.sink_file + (result.scope.sink_line ? ':' + result.scope.sink_line : '')
                    : '',
                short: result.scope.sink_file
                    ? shortPath(result.scope.sink_file, 2) +
                      (result.scope.sink_line ? ':' + result.scope.sink_line : '')
                    : label('validateScopeNoSink', '(no sink file resolved)'),
                mono: !!result.scope.sink_file,
                muted: !result.scope.sink_file,
            },
        ];
        scopeRows.forEach(function (row) {
            const item = document.createElement('div');
            item.className = 'oasis-assistant-validate-scope-row';
            const k = document.createElement('span');
            k.className = 'oasis-assistant-validate-scope-key';
            k.textContent = row.label;
            const v = document.createElement('span');
            v.className =
                'oasis-assistant-validate-scope-val' +
                (row.mono ? ' oasis-assistant-validate-scope-val--mono' : '') +
                (row.muted ? ' oasis-assistant-validate-scope-val--muted' : '');
            v.textContent = row.short || '—';
            if (row.full && row.full !== row.short) {
                v.title = row.full;
            }
            item.appendChild(k);
            item.appendChild(v);
            scope.appendChild(item);
        });
        container.appendChild(scope);
    }

    const appendCitation = function (parent, cit) {
        if (!cit || typeof cit !== 'object') {
            return;
        }
        const p = cit.file_path || '';
        const start = cit.start_line || '';
        const full = p + (start ? ':' + start : '');
        const short = shortPath(p, 2) + (start ? ':' + start : '');
        const span = document.createElement('span');
        span.className = 'oasis-assistant-validate-citation';
        span.title = full;
        span.textContent = short;
        parent.appendChild(span);
    };

    const appendSeverityClassSuffix = function (raw) {
        const allowed =
            DashboardApp.ASSISTANT_VALIDATE_SEVERITY_SUFFIXES ||
            ['info', 'low', 'medium', 'high', 'critical'];
        const s = String(raw || '').trim().toLowerCase();
        return allowed.indexOf(s) !== -1 ? s : 'info';
    };

    // Evidence section builder — each group gets a <details> so the user can
    // collapse long lists while still being able to reach every hit via a
    // bounded, scrollable inner container.
    const evidenceWrap = document.createElement('div');
    evidenceWrap.className = 'oasis-assistant-validate-evidence';

    const appendGroup = function (groupKey, titleText, items, fillItem, opts) {
        if (!Array.isArray(items) || items.length === 0) {
            return;
        }
        const options = opts || {};
        const details = document.createElement('details');
        details.className =
            'oasis-assistant-validate-group oasis-assistant-validate-group--' + groupKey;
        if (options.open !== false) {
            details.open = true;
        }
        const summary = document.createElement('summary');
        summary.className = 'oasis-assistant-validate-group-head';
        const hName = document.createElement('span');
        hName.className = 'oasis-assistant-validate-group-name';
        hName.textContent = titleText;
        const hCount = document.createElement('span');
        hCount.className = 'oasis-assistant-validate-group-count';
        hCount.textContent = String(items.length);
        summary.appendChild(hName);
        summary.appendChild(hCount);
        details.appendChild(summary);

        const scroll = document.createElement('div');
        scroll.className =
            'oasis-assistant-validate-scroll oasis-assistant-validate-scroll--' + groupKey;
        const list = document.createElement('ul');
        list.className = 'oasis-assistant-validate-list';
        items.forEach(function (item) {
            const li = document.createElement('li');
            li.className = 'oasis-assistant-validate-item';
            fillItem(item, li);
            list.appendChild(li);
        });
        scroll.appendChild(list);
        details.appendChild(scroll);
        evidenceWrap.appendChild(details);
    };

    appendGroup(
        'entries',
        label('validateEntryPointsLabel', 'Entry points'),
        result.entry_points,
        function (ep, li) {
            const tag = document.createElement('span');
            tag.className = 'oasis-assistant-validate-tag';
            tag.textContent = ep.framework || '';
            li.appendChild(tag);
            li.appendChild(document.createTextNode(' '));
            const kind = document.createElement('code');
            kind.textContent = ep.label || '';
            li.appendChild(kind);
            if (ep.route) {
                li.appendChild(document.createTextNode(' '));
                const route = document.createElement('span');
                route.className = 'oasis-assistant-validate-route';
                route.textContent = ep.route;
                li.appendChild(route);
            }
            li.appendChild(document.createTextNode(' '));
            appendCitation(li, ep.citation);
        }
    );
    appendGroup(
        'paths',
        label('validatePathsLabel', 'Execution paths'),
        result.execution_paths,
        function (path, li) {
            const hops = Array.isArray(path.hops) ? path.hops.length : 0;
            if (path.entry_point) {
                const entry = document.createElement('span');
                entry.textContent =
                    path.entry_point.route || path.entry_point.label || '';
                li.appendChild(entry);
            } else {
                const none = document.createElement('em');
                none.className = 'oasis-assistant-validate-none';
                none.textContent = 'no entry';
                li.appendChild(none);
            }
            li.appendChild(document.createTextNode(' '));
            const sep = document.createElement('span');
            sep.className = 'oasis-assistant-validate-sep';
            sep.textContent = '\u2192';
            li.appendChild(sep);
            li.appendChild(
                document.createTextNode(' ' + String(hops) + ' hop(s)')
            );
        }
    );
    appendGroup(
        'flows',
        label('validateFlowsLabel', 'Taint flows'),
        result.taint_flows,
        function (flow, li) {
            const src = document.createElement('code');
            src.textContent = flow.source_kind || '';
            li.appendChild(src);
            li.appendChild(document.createTextNode(' '));
            const sep = document.createElement('span');
            sep.className = 'oasis-assistant-validate-sep';
            sep.textContent = '\u2192';
            li.appendChild(sep);
            li.appendChild(document.createTextNode(' '));
            const sk = document.createElement('code');
            sk.textContent = flow.sink_kind || '';
            li.appendChild(sk);
            li.appendChild(document.createTextNode(' '));
            appendCitation(li, flow.sink_citation);
        }
    );
    appendGroup(
        'mitigations',
        label('validateMitigationsLabel', 'Mitigations'),
        result.mitigations,
        function (m, li) {
            const kind = document.createElement('code');
            kind.textContent = m.kind || '';
            li.appendChild(kind);
            if (m.nullifies) {
                const mark = document.createElement('span');
                mark.className = 'oasis-assistant-validate-null';
                mark.title = 'nullifies the finding';
                mark.textContent = '\u2713';
                li.appendChild(mark);
            }
            li.appendChild(document.createTextNode(' '));
            appendCitation(li, m.citation);
        }
    );
    appendGroup(
        'controls',
        label('validateControlsLabel', 'Access controls'),
        result.control_checks,
        function (c, li) {
            const kind = document.createElement('code');
            kind.textContent = c.kind || '';
            li.appendChild(kind);
            li.appendChild(document.createTextNode(' '));
            const pill = document.createElement('span');
            pill.className =
                'oasis-assistant-validate-ctrl ' +
                (c.present
                    ? 'oasis-assistant-validate-ctrl--ok'
                    : 'oasis-assistant-validate-ctrl--missing');
            pill.textContent = c.present ? 'present' : 'missing';
            li.appendChild(pill);
        }
    );
    appendGroup(
        'config',
        label('validateConfigLabel', 'Config findings'),
        result.config_findings,
        function (f, li) {
            const kind = document.createElement('code');
            kind.textContent = f.kind || '';
            li.appendChild(kind);
            li.appendChild(document.createTextNode(' '));
            const sevSlug = appendSeverityClassSuffix(f.severity);
            const sev = document.createElement('span');
            sev.className =
                'oasis-assistant-validate-sev oasis-assistant-validate-sev--' + sevSlug;
            sev.textContent = sevSlug;
            li.appendChild(sev);
            li.appendChild(document.createTextNode(' '));
            appendCitation(li, f.citation);
        }
    );

    if (evidenceWrap.childNodes.length > 0) {
        container.appendChild(evidenceWrap);
    }

    if (Array.isArray(result.errors) && result.errors.length) {
        const errBox = document.createElement('div');
        errBox.className = 'oasis-assistant-validate-errors';
        const h = document.createElement('strong');
        h.textContent = label('validateErrorsLabel', 'Errors');
        errBox.appendChild(h);
        const ul = document.createElement('ul');
        result.errors.forEach(function (e) {
            const li = document.createElement('li');
            li.textContent = String(e);
            ul.appendChild(li);
        });
        errBox.appendChild(ul);
        container.appendChild(errBox);
    }
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
        const o = {
            role: m.role,
            content: typeof m.content === 'string' ? m.content : '',
            at: typeof m.at === 'string' ? m.at : '',
        };
        if (m.role === 'assistant') {
            if (typeof m.visible_markdown === 'string') {
                o.visible_markdown = m.visible_markdown;
            }
            if (Array.isArray(m.thought_segments)) {
                o.thought_segments = m.thought_segments;
            }
        }
        return o;
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
 * Map a report / stored model name to one of the Ollama chat model option strings.
 *
 * ``optionValues`` entries are normalized with ``String`` once. Per-option ``toLowerCase()`` and
 * family-tag parsing are precomputed so predicates do not repeat ``String`` / ``toLowerCase`` work.
 * Returns ``''`` when nothing matches (public contract: always a string).
 *
 * Precedence (first hit wins):
 *   1. Exact string match in the normalized option list
 *   2. Case-insensitive exact match (returns the option’s canonical casing from the list)
 *   3. Prefix match: option starts with ``seed``, or ``seed`` starts with option (rename drift)
 *   4. Same tag before ``:`` as ``seed`` (model family), e.g. ``llama3`` vs ``llama3:8b``
 *   5. Option string starts with the seed’s family prefix (lowercase)
 *
 * Used when localStorage is empty so the default matches the model that generated the report.
 */
DashboardApp.matchChatModelToOptions = function (reportModel, optionValues) {
    if (!reportModel || typeof reportModel !== 'string' || !String(reportModel).trim()) {
        return '';
    }
    const seed = String(reportModel).trim();
    const opts = Array.isArray(optionValues) ? optionValues.map(String) : [];
    const lower = seed.toLowerCase();
    const seedParts = seed.split(':');
    const fam = seedParts.length > 1 ? seedParts[0].trim() : seed;
    const famLower = fam.toLowerCase();

    const optsLower = opts.map(function (s) {
        return s.toLowerCase();
    });
    const optFamPrefix = opts.map(function (s) {
        const parts = s.split(':');
        return parts.length > 1 ? parts[0].trim() : s;
    });
    const optFamPrefixLower = optFamPrefix.map(function (p) {
        return p.toLowerCase();
    });

    let i;
    let s;

    // 1 — exact
    if (opts.indexOf(seed) >= 0) {
        return seed;
    }
    // 2 — case-insensitive exact (reuse optsLower / lower)
    for (i = 0; i < opts.length; i++) {
        if (optsLower[i] === lower) {
            return opts[i];
        }
    }
    // 3 — bidirectional prefix
    for (i = 0; i < opts.length; i++) {
        s = opts[i];
        if (s.indexOf(seed) === 0 || seed.indexOf(s) === 0) {
            return s;
        }
    }
    // 4 — family tag before ":" (reuse optFamPrefix / optFamPrefixLower; require truthy prefix like original)
    for (i = 0; i < opts.length; i++) {
        if (optFamPrefix[i] && fam && optFamPrefixLower[i] === famLower) {
            return opts[i];
        }
    }
    // 5 — full option string starts with family prefix
    for (i = 0; i < opts.length; i++) {
        if (fam && optsLower[i].indexOf(famLower) === 0) {
            return opts[i];
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
    const resetSelect = function (sel) {
        DashboardApp._clearElement(sel);
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = noneText;
        sel.appendChild(opt);
    };
    const files =
        payload && typeof payload === 'object' && Array.isArray(payload.files) ? payload.files : [];
    panelRoot._oasisAssistantFiles = files;
    panelRoot._oasisAssistantPayload = payload && typeof payload === 'object' ? payload : null;
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

    const selectedIndex = function (sel) {
        const v = sel && sel.value;
        if (v === '' || v === undefined || v === null) {
            return NaN;
        }
        const n = Number(v);
        return Number.isFinite(n) ? n : NaN;
    };

    const resetSelect = function (sel) {
        DashboardApp._clearElement(sel);
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = noneText;
        sel.appendChild(opt);
    };

    const chunkOptionLabel = function (chunk, index) {
        let base = txt('findingChunkLabel', 'Chunk') + ' ' + (index + 1);
        if (chunk && chunk.start_line != null && chunk.end_line != null) {
            base += ' (lines ' + chunk.start_line + '–' + chunk.end_line + ')';
        }
        return DashboardApp._truncateAssistantLabel(base, 96);
    };

    const renderChunksForFile = function (files, fi) {
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
    };

    const renderFindingsForChunk = function (files, fi, ci) {
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
    };

    const onFileChange = function () {
        const files = panelRoot._oasisAssistantFiles || [];
        const fi = selectedIndex(selFi);
        if (!Number.isFinite(fi) || fi < 0 || fi >= files.length) {
            resetSelect(selCi);
            resetSelect(selGi);
            return;
        }
        renderChunksForFile(files, fi);
    };

    const onChunkChange = function () {
        const files = panelRoot._oasisAssistantFiles || [];
        const fi = selectedIndex(selFi);
        const ci = selectedIndex(selCi);
        renderFindingsForChunk(files, fi, ci);
    };

    const notifyFindingSelection = function () {
        if (typeof panelRoot._oasisAssistantFindingSelectionCallback === 'function') {
            panelRoot._oasisAssistantFindingSelectionCallback();
        }
    };

    selFi.addEventListener('change', function () {
        onFileChange();
        notifyFindingSelection();
    });
    selCi.addEventListener('change', function () {
        onChunkChange();
        notifyFindingSelection();
    });
    selGi.addEventListener('change', notifyFindingSelection);
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
            if (typeof panelRoot._oasisAssistantFindingSelectionCallback === 'function') {
                panelRoot._oasisAssistantFindingSelectionCallback();
            }
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

    const fillVulnReportList = function (rows) {
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
    };

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
            if (typeof panelRoot._oasisAssistantFindingSelectionCallback === 'function') {
                panelRoot._oasisAssistantFindingSelectionCallback();
            }
            return;
        }
        DashboardApp.fetchReportJsonPayload(rel)
            .then(function (payload) {
                if (!payload || typeof payload !== 'object') {
                    DashboardApp.populateAssistantFindingSelectorsFromPayload(panelRoot, txt, {
                        files: [],
                    });
                } else {
                    DashboardApp.populateAssistantFindingSelectorsFromPayload(panelRoot, txt, payload);
                }
                if (typeof panelRoot._oasisAssistantFindingSelectionCallback === 'function') {
                    panelRoot._oasisAssistantFindingSelectionCallback();
                }
            })
            .catch(function () {
                DashboardApp.populateAssistantFindingSelectorsFromPayload(panelRoot, txt, { files: [] });
                if (typeof panelRoot._oasisAssistantFindingSelectionCallback === 'function') {
                    panelRoot._oasisAssistantFindingSelectionCallback();
                }
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

    const pathEntry =
        DashboardApp.reportFormatsByPath && DashboardApp.reportFormatsByPath[reportPath];
    const scopedReport = pathEntry && pathEntry.report ? pathEntry.report : null;
    const codebaseBroken = !!(scopedReport && scopedReport.codebase_accessible === false);
    const codebaseWarningBanner = codebaseBroken
        ? `<div class="oasis-assistant-codebase-warning" role="alert" title="${DashboardApp._escapeHtml(
              txt('codebaseUnavailableDetail', '')
          )}">
          <div class="oasis-assistant-codebase-warning__headline">
            <span class="oasis-assistant-codebase-warning__emoji" aria-hidden="true">⚠️</span>
            <strong class="oasis-assistant-codebase-warning__title">${DashboardApp._escapeHtml(
                txt('codebaseUnavailableShort', 'Codebase unreachable')
            )}</strong>
          </div>
          <p class="oasis-assistant-codebase-warning__body">${DashboardApp._escapeHtml(
              txt('codebaseUnavailableDetail', '')
          )}</p>
        </div>`
        : '';

    const contextBadgeText = execSummary
        ? txt('contextExecutiveAggregate', 'Context: full scan (aggregate JSON)')
        : txt('contextSingleVuln', 'Context: single vulnerability report');
    const findingHiddenClass = showFindingRefBlock ? '' : ' oasis-assistant-finding-ref--hidden';
    const validateTargetWrapClass = showFindingRefBlock ? '' : ' oasis-assistant-validate-target-wrap--hidden';
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
            ${codebaseWarningBanner}
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
                <div class="oasis-assistant-validate-row">
                    <div class="oasis-assistant-validate-target-wrap${validateTargetWrapClass}">
                        <div id="oasis-assistant-validate-target" class="oasis-assistant-validate-target" aria-live="polite"></div>
                    </div>
                    <button type="button" class="btn btn-secondary" id="oasis-assistant-validate-btn">${DashboardApp._escapeHtml(txt('validateButton', 'Validate this finding'))}</button>
                    <div id="oasis-assistant-validate-panel" class="oasis-assistant-validate-panel" hidden></div>
                </div>
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
            <div class="oasis-assistant-compose-row">
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

    const refreshFindingUi = function () {
        DashboardApp.updateAssistantValidateTargetSummary(panel, txt);
        return DashboardApp.refreshAssistantVerdictPanelFromSession(panel, txt);
    };
    panel._oasisAssistantFindingSelectionCallback = refreshFindingUi;

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
    if (showFindingRefBlock) {
        refreshFindingUi();
    }

    const chatModelLsKey = DashboardApp._assistantChatModelStorageKey(reportPath);
    const chatModelSelect = panel.querySelector('#oasis-assistant-chat-model');
    let activeChatModel = '';
    /** Monotonic guard so overlapping model-switch chains cannot reorder UI state. */
    let chatModelSwitchSeq = 0;
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
            const next = chatModelSelect.value ? String(chatModelSelect.value).trim() : '';
            try {
                window.localStorage.setItem(chatModelLsKey, next || '');
            } catch (e) {
                /* ignore */
            }
            const prev = activeChatModel || '';
            const sid = DashboardApp._assistantSessionId;
            const payloadPreview = panel._oasisAssistantPayload;
            const vnSwitch =
                payloadPreview && typeof payloadPreview.vulnerability_name === 'string'
                    ? payloadPreview.vulnerability_name.trim()
                    : '';
            const validateBtnSwitch = panel.querySelector('#oasis-assistant-validate-btn');

            if (!prev || prev === next) {
                activeChatModel = next;
                return;
            }
            if (!sid) {
                activeChatModel = next;
                return;
            }

            const switchSeq = ++chatModelSwitchSeq;
            const staleModelSwitch = { _oasisStaleModelSwitch: true };
            const assertFreshSwitch = function () {
                if (switchSeq !== chatModelSwitchSeq) {
                    return Promise.reject(staleModelSwitch);
                }
                return Promise.resolve();
            };

            chatModelSelect.disabled = true;
            if (validateBtnSwitch) {
                validateBtnSwitch.disabled = true;
            }
            sendBtn.disabled = true;
            DashboardApp.postAssistantSessionBranch({
                report_path: reportPath,
                session_id: sid,
                model: prev,
                messages: DashboardApp._assistantMessagesForApi(),
                vulnerability_name: vnSwitch,
            })
                .then(function () {
                    return assertFreshSwitch().then(function () {
                        return DashboardApp.fetchAssistantSession(reportPath, sid);
                    });
                })
                .then(function (doc) {
                    return assertFreshSwitch().then(function () {
                        if (!doc || typeof doc !== 'object') {
                            throw new Error('session');
                        }
                        const branches =
                            doc.model_branches && typeof doc.model_branches === 'object'
                                ? doc.model_branches
                                : {};
                        const br = branches[next];
                        const rawMsgs = br && Array.isArray(br.messages) ? br.messages : [];
                        const trimmed = DashboardApp._trimAssistantMessages(rawMsgs);
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
                        activeChatModel = next;
                        chatModelSelect.value = next;
                        renderLog();
                        DashboardApp.updateAssistantValidateTargetSummary(panel, txt);
                        const vPanelSw = panel.querySelector('#oasis-assistant-validate-panel');
                        const fkSw = DashboardApp.findingValidationStorageKey(
                            DashboardApp._gatherAssistantFindingIndices(panel)
                        );
                        const rawMapSw = br && br.finding_validations;
                        const fvSw =
                            fkSw &&
                            rawMapSw &&
                            typeof rawMapSw === 'object' &&
                            typeof rawMapSw[fkSw] === 'object'
                                ? rawMapSw[fkSw]
                                : null;
                        if (vPanelSw) {
                            if (fvSw) {
                                vPanelSw.hidden = false;
                                DashboardApp.renderAssistantVerdictPanel(vPanelSw, fvSw, txt);
                            } else {
                                vPanelSw.hidden = true;
                                DashboardApp._clearElement(vPanelSw);
                            }
                        }
                        return DashboardApp.postAssistantSessionBranch({
                            report_path: reportPath,
                            session_id: sid,
                            model: next,
                            messages: DashboardApp._assistantMessagesForApi(),
                            vulnerability_name: vnSwitch,
                            set_as_active: true,
                        });
                    });
                })
                .catch(function (err) {
                    if (err && err._oasisStaleModelSwitch) {
                        return;
                    }
                    try {
                        chatModelSelect.value = prev;
                    } catch (e2) {
                        /* ignore */
                    }
                })
                .finally(function () {
                    if (switchSeq !== chatModelSwitchSeq) {
                        return;
                    }
                    chatModelSelect.disabled = false;
                    if (validateBtnSwitch) {
                        validateBtnSwitch.disabled = false;
                    }
                    sendBtn.disabled = false;
                });
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

    /**
     * Append a live assistant message placeholder whose body is updated
     * incrementally as streaming deltas arrive. Returns accessors to
     * append raw text (``appendText``), drop the placeholder if the
     * stream never produced anything usable (``remove``) and finalize
     * the row with a rich assistant payload (``finalize``).
     *
     * Auto-scroll is throttled via ``requestAnimationFrame`` so that
     * high-frequency deltas do not jank the log. The placeholder keeps
     * the raw streamed text inside a ``<pre>`` block during streaming
     * and switches to full markdown rendering on finalize.
     */
    const appendLiveAssistantMsg = function () {
        const row = document.createElement('div');
        row.className = 'oasis-assistant-msg oasis-assistant-msg--assistant oasis-assistant-msg--streaming';
        const hd = document.createElement('div');
        hd.className = 'oasis-assistant-msg-hd';
        hd.textContent = txt('msgLabelAssistant', 'Assistant');
        const body = document.createElement('div');
        body.className = 'oasis-assistant-msg-body oasis-assistant-msg-body--rich';

        // Reasoning (``thinking`` channel) lives in a collapsible block so it
        // doesn't pollute the answer. Element is created lazily on first delta.
        let thinkingBlock = null;
        let thinkingPre = null;
        const ensureThinkingBlock = function () {
            if (thinkingBlock) {
                return;
            }
            thinkingBlock = document.createElement('details');
            thinkingBlock.className = 'oasis-assistant-think oasis-assistant-think--live';
            thinkingBlock.open = true;
            const summary = document.createElement('summary');
            summary.textContent = txt('msgLabelReasoning', 'Reasoning');
            thinkingPre = document.createElement('pre');
            thinkingPre.className = 'oasis-assistant-think-pre';
            thinkingBlock.appendChild(summary);
            thinkingBlock.appendChild(thinkingPre);
            body.insertBefore(thinkingBlock, body.firstChild);
        };

        const streamNode = document.createElement('pre');
        streamNode.className = 'oasis-assistant-stream';
        const cursor = document.createElement('span');
        cursor.className = 'oasis-assistant-stream-cursor';
        cursor.setAttribute('aria-hidden', 'true');
        cursor.textContent = '▍';
        body.appendChild(streamNode);
        body.appendChild(cursor);
        row.appendChild(hd);
        row.appendChild(body);
        logEl.appendChild(row);
        logEl.scrollTop = logEl.scrollHeight;

        let accumulated = '';
        let thinkingAcc = '';
        let scrollScheduled = false;
        const scheduleScroll = function () {
            if (scrollScheduled) {
                return;
            }
            scrollScheduled = true;
            window.requestAnimationFrame(function () {
                scrollScheduled = false;
                logEl.scrollTop = logEl.scrollHeight;
            });
        };

        return {
            row: row,
            appendText: function (text, channel) {
                if (!text) {
                    return;
                }
                const safe = String(text);
                if (channel === 'thinking') {
                    thinkingAcc += safe;
                    ensureThinkingBlock();
                    thinkingPre.textContent = thinkingAcc;
                } else {
                    accumulated += safe;
                    streamNode.textContent = accumulated;
                }
                scheduleScroll();
            },
            getAccumulated: function () {
                return accumulated;
            },
            getThinking: function () {
                return thinkingAcc;
            },
            remove: function () {
                if (row.parentNode) {
                    row.parentNode.removeChild(row);
                }
            },
            finalize: function (payload) {
                row.classList.remove('oasis-assistant-msg--streaming');
                if (cursor.parentNode) {
                    cursor.parentNode.removeChild(cursor);
                }
                if (thinkingBlock && thinkingBlock.parentNode) {
                    thinkingBlock.parentNode.removeChild(thinkingBlock);
                }
                const acc = accumulated.trim();
                const merged =
                    payload && typeof payload === 'object'
                        ? Object.assign({}, payload)
                        : { message: typeof payload === 'string' ? payload : '' };
                const msgStr = typeof merged.message === 'string' ? merged.message : '';
                const visStr =
                    typeof merged.visible_markdown === 'string' ? merged.visible_markdown : '';
                if (
                    acc &&
                    (!msgStr || !msgStr.trim()) &&
                    (!visStr || !visStr.trim())
                ) {
                    merged.message = acc;
                }
                body.innerHTML = DashboardApp.renderAssistantMessageHtml(merged);
                logEl.scrollTop = logEl.scrollHeight;
                wireMdCodeCopy();
            },
        };
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
        const vClear = panel.querySelector('#oasis-assistant-validate-panel');
        if (vClear) {
            vClear.hidden = true;
            DashboardApp._clearElement(vClear);
        }
        const vTargetEl = panel.querySelector('#oasis-assistant-validate-target');
        if (vTargetEl) {
            DashboardApp._clearElement(vTargetEl);
        }
        if (chatModelSelect && cachedSortedChatModels.length) {
            applyAssistantChatModelSeed(cachedSortedChatModels, reportPreferredModelStr);
        }
        activeChatModel =
            chatModelSelect && chatModelSelect.value ? String(chatModelSelect.value).trim() : '';
        refreshSessionList(DashboardApp._assistantSessionId);
    };

    const getValidStoredChatModel = function (sortedNames) {
        if (!Array.isArray(sortedNames) || sortedNames.length === 0) {
            return '';
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
        const scoped = typeof lsScoped === 'string' ? lsScoped.trim() : '';
        const legacy = typeof lsLegacy === 'string' ? lsLegacy.trim() : '';
        if (scoped && sortedNames.indexOf(scoped) >= 0) {
            return scoped;
        }
        if (legacy && sortedNames.indexOf(legacy) >= 0) {
            return legacy;
        }
        return '';
    };

    /**
     * Choose the chat-model ``<select>`` value when opening the panel.
     *
     * Behavior (in order): valid scoped or legacy localStorage → else map ``seedPreferred`` (report
     * JSON ``model_name`` / ``deep_model`` / …) onto ``sortedNames`` via ``matchChatModelToOptions``
     * (exact, case, prefix, family heuristics) → else first Ollama option. When the report string no
     * longer matches any live option (e.g. model removed from Ollama), mapping fails and we fall back
     * to the first listed model — users can still pick another; branch restore on session load uses
     * ``resolveReportPreferredBranchModelKey`` separately.
     */
    const applyAssistantChatModelSeed = function (sortedNames, seedPreferred) {
        if (!chatModelSelect) {
            return;
        }
        if (!Array.isArray(sortedNames) || sortedNames.length === 0) {
            return;
        }
        const seed = typeof seedPreferred === 'string' ? seedPreferred.trim() : '';
        let pick = getValidStoredChatModel(sortedNames);
        if (!pick && seed) {
            pick = DashboardApp.matchChatModelToOptions(seed, sortedNames) || '';
        }
        if (!pick && sortedNames.length > 0) {
            pick = sortedNames[0];
        }
        if (pick) {
            chatModelSelect.value = pick;
        }
    };

    /** Set ``select.value`` only when an ``<option>`` with that ``value`` exists (avoids invalid state). */
    const setChatModelSelectIfOptionMatches = function (selectEl, modelValue) {
        if (!selectEl || !modelValue) {
            return;
        }
        const hit = Array.prototype.find.call(selectEl.querySelectorAll('option'), function (opt) {
            return opt.value === modelValue;
        });
        if (hit) {
            selectEl.value = modelValue;
        }
    };

    /** Messages for ``modelKey`` within ``model_branches`` (or ``[]``); sync select to ``modelKey`` when present. */
    const pickBranchMessagesForReportModel = function (selectEl, branches, modelKey) {
        const br = branches && modelKey ? branches[modelKey] : null;
        const raw = br && Array.isArray(br.messages) ? br.messages : [];
        setChatModelSelectIfOptionMatches(selectEl, modelKey);
        return raw;
    };

    /**
     * Branch key to load when preferring the report model without localStorage: align with Ollama options
     * via ``DashboardApp.matchChatModelToOptions``, then fall back to ``model_branches`` keys so stored
     * sessions still resolve after renames when branch keys are not a subset of current option strings.
     */
    const resolveReportPreferredBranchModelKey = function (preferredStr, branches, sortedOptions) {
        const kOptions = DashboardApp.matchChatModelToOptions(preferredStr, sortedOptions);
        if (kOptions) {
            return kOptions;
        }
        if (!preferredStr || !branches || typeof branches !== 'object') {
            return '';
        }
        const pref = String(preferredStr).trim();
        if (!pref) {
            return '';
        }
        if (Object.prototype.hasOwnProperty.call(branches, pref)) {
            return pref;
        }
        const lower = pref.toLowerCase();
        const keys = Object.keys(branches);
        for (let bi = 0; bi < keys.length; bi++) {
            if (keys[bi].toLowerCase() === lower) {
                return keys[bi];
            }
        }
        return '';
    };

    const syncChatModelFromSessionDoc = function (doc) {
        if (!chatModelSelect || !doc || typeof doc !== 'object') {
            return;
        }
        const m = typeof doc.model === 'string' ? doc.model.trim() : '';
        if (!m) {
            return;
        }
        setChatModelSelectIfOptionMatches(chatModelSelect, m);
    };

    const loadSessionById = function (sessionId, loadOpts) {
        const opts = loadOpts && typeof loadOpts === 'object' ? loadOpts : {};
        if (!sessionId) {
            startNewChat();
            return Promise.resolve();
        }
        return DashboardApp.fetchAssistantSession(reportPath, sessionId)
            .then(function (doc) {
                const branches =
                    doc.model_branches && typeof doc.model_branches === 'object' ? doc.model_branches : {};
                let raw = Array.isArray(doc.messages) ? doc.messages : [];
                let useReportWhenNoStore = false;
                // No chat-model localStorage: prefer the conversation stored under the report's model.
                if (
                    opts.useReportModelIfNoStored === true &&
                    reportPreferredModelStr
                ) {
                    // (1) Branch selection: map report JSON model string → a key in model_branches (via
                    // Ollama option list first, then exact/case keys on branches — see resolver).
                    const reportBranchKey = resolveReportPreferredBranchModelKey(
                        reportPreferredModelStr,
                        branches,
                        cachedSortedChatModels
                    );
                    // (2) Message loading: if we resolved a branch, use its messages and align the select;
                    // otherwise fall through to doc.messages + doc.model below.
                    if (reportBranchKey) {
                        raw = pickBranchMessagesForReportModel(
                            chatModelSelect,
                            branches,
                            reportBranchKey
                        );
                        useReportWhenNoStore = true;
                    }
                }
                if (!useReportWhenNoStore) {
                    raw = Array.isArray(doc.messages) ? doc.messages : [];
                    syncChatModelFromSessionDoc(doc);
                }
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
                renderLog();
                activeChatModel =
                    chatModelSelect && chatModelSelect.value
                        ? String(chatModelSelect.value).trim()
                        : '';
                const vPanelLd = panel.querySelector('#oasis-assistant-validate-panel');
                if (vPanelLd) {
                    DashboardApp.updateAssistantValidateTargetSummary(panel, txt);
                    const mk = activeChatModel;
                    const branches =
                        doc.model_branches && typeof doc.model_branches === 'object'
                            ? doc.model_branches
                            : {};
                    const br = mk ? branches[mk] : null;
                    const fkLd = DashboardApp.findingValidationStorageKey(
                        DashboardApp._gatherAssistantFindingIndices(panel)
                    );
                    const rawMapLd = br && br.finding_validations;
                    const fvLd =
                        fkLd &&
                        rawMapLd &&
                        typeof rawMapLd === 'object' &&
                        typeof rawMapLd[fkLd] === 'object'
                            ? rawMapLd[fkLd]
                            : null;
                    if (fvLd) {
                        vPanelLd.hidden = false;
                        DashboardApp.renderAssistantVerdictPanel(vPanelLd, fvLd, txt);
                    } else {
                        vPanelLd.hidden = true;
                        DashboardApp._clearElement(vPanelLd);
                    }
                }
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

    const validateBtn = panel.querySelector('#oasis-assistant-validate-btn');
    const validatePanel = panel.querySelector('#oasis-assistant-validate-panel');
    if (validateBtn && validatePanel) {
        validateBtn.addEventListener('click', function () {
            const indices = DashboardApp._gatherAssistantFindingIndices(panel);
            // Resolve the selected file/chunk/finding locally so the request
            // is self-contained (visible in Network tab) and the server can
            // cross-check indices against the declared sink hints.
            const files = Array.isArray(panel._oasisAssistantFiles) ? panel._oasisAssistantFiles : [];
            let sinkFilePath = null;
            let sinkLineHint = null;
            if (
                Number.isFinite(indices.file_index) &&
                indices.file_index >= 0 &&
                indices.file_index < files.length
            ) {
                const fileEntry = files[indices.file_index] || {};
                if (typeof fileEntry.file_path === 'string' && fileEntry.file_path.trim()) {
                    sinkFilePath = fileEntry.file_path.trim();
                }
                const chunks = Array.isArray(fileEntry.chunk_analyses) ? fileEntry.chunk_analyses : [];
                if (
                    Number.isFinite(indices.chunk_index) &&
                    indices.chunk_index >= 0 &&
                    indices.chunk_index < chunks.length
                ) {
                    const chunk = chunks[indices.chunk_index] || {};
                    const findings = Array.isArray(chunk.findings) ? chunk.findings : [];
                    if (
                        Number.isFinite(indices.finding_index) &&
                        indices.finding_index >= 0 &&
                        indices.finding_index < findings.length
                    ) {
                        const finding = findings[indices.finding_index] || {};
                        const candidate =
                            typeof finding.snippet_start_line === 'number' && finding.snippet_start_line > 0
                                ? finding.snippet_start_line
                                : typeof chunk.start_line === 'number' && chunk.start_line > 0
                                ? chunk.start_line
                                : null;
                        sinkLineHint = candidate;
                    } else if (typeof chunk.start_line === 'number' && chunk.start_line > 0) {
                        sinkLineHint = chunk.start_line;
                    }
                }
            }
            const payloadPreview = panel._oasisAssistantPayload;
            const payloadVulnName =
                payloadPreview && typeof payloadPreview.vulnerability_name === 'string'
                    ? payloadPreview.vulnerability_name.trim()
                    : '';
            const validatePayload = {
                report_path: reportPath,
                file_index: indices.file_index,
                chunk_index: indices.chunk_index,
                finding_index: indices.finding_index,
            };
            if (indices.finding_scope_report_path) {
                validatePayload.finding_scope_report_path = indices.finding_scope_report_path;
            }
            if (payloadVulnName) {
                validatePayload.vulnerability_name = payloadVulnName;
            }
            if (sinkFilePath) {
                validatePayload.sink_file = sinkFilePath;
            }
            if (sinkLineHint != null) {
                validatePayload.sink_line = sinkLineHint;
            }
            const validateModel =
                chatModelSelect && chatModelSelect.value
                    ? String(chatModelSelect.value).trim()
                    : '';
            if (validateModel) {
                validatePayload.model = validateModel;
            }
            if (!DashboardApp._assistantSessionId) {
                DashboardApp._assistantSessionId = DashboardApp._newAssistantSessionId();
            }
            validatePayload.session_id = DashboardApp._assistantSessionId;
            const originalLabel = validateBtn.textContent;
            validateBtn.disabled = true;
            validateBtn.textContent = txt('validateRunning', 'Validating…');
            validatePanel.hidden = false;
            validatePanel.textContent = txt('validateRunning', 'Validating…');
            DashboardApp.postAssistantInvestigate(validatePayload)
                .then(function (result) {
                    DashboardApp.renderAssistantVerdictPanel(validatePanel, result, txt);
                    const anchor =
                        'OASIS finding validation finished for the selected finding. The full structured verdict (status, evidence, narrative) is stored for this chat model — ask for a PoC, clarifications, or next steps.';
                    const nowIso = new Date().toISOString();
                    appendUserMsg(anchor);
                    DashboardApp._assistantConversation.push({
                        role: 'user',
                        content: anchor,
                        at: nowIso,
                    });
                    DashboardApp._assistantConversation = DashboardApp._trimAssistantMessages(
                        DashboardApp._assistantConversation
                    );
                    rebuildQuestionIndex();
                    wireMdCodeCopy();
                    const vnPersist = payloadVulnName || '';
                    const cmPersist =
                        validateModel ||
                        (chatModelSelect && chatModelSelect.value
                            ? String(chatModelSelect.value).trim()
                            : '');
                    return DashboardApp.postAssistantSessionBranch({
                        report_path: reportPath,
                        session_id: DashboardApp._assistantSessionId,
                        model: cmPersist,
                        messages: DashboardApp._assistantMessagesForApi(),
                        vulnerability_name: vnPersist,
                        set_as_active: true,
                    })
                        .then(function () {
                            return refreshSessionList(DashboardApp._assistantSessionId);
                        })
                        .catch(function () {
                            return refreshSessionList(DashboardApp._assistantSessionId);
                        });
                })
                .catch(function (err) {
                    const msg = DashboardApp._errorMessage(err) || 'unknown error';
                    validatePanel.textContent = txt('validateErrorPrefix', 'Validation failed: ') + msg;
                })
                .finally(function () {
                    validateBtn.disabled = false;
                    validateBtn.textContent = originalLabel;
                });
        });
    }

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
        const indices = DashboardApp._gatherAssistantFindingIndices(panel);
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

        let live = null;
        let streamingErrorShown = false;

        const applyFinalReply = function (data) {
            if (budgetHintEl) {
                budgetHintEl.textContent = formatBudgetHint(data.system_budget_chars);
            }
            const answer = typeof data.message === 'string' ? data.message : '';
            const replyPayload = {
                message: answer,
                visible_markdown: data.visible_markdown,
                thought_segments: data.thought_segments,
            };
            if (live) {
                live.finalize(replyPayload);
            } else {
                appendAssistantMsg(replyPayload);
            }
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
        };

        const applyError = function (err) {
            if (live) {
                live.remove();
            }
            if (streamingErrorShown) {
                const msg = DashboardApp._errorMessage(err);
                appendAssistantMsg({
                    message:
                        txt('fallbackErrorPrefix', 'Could not complete request: ') + msg,
                });
                return;
            }
            const msg = DashboardApp._errorMessage(err);
            appendAssistantMsg({ message: 'Error: ' + msg });
        };

        const runNonStreamingFallback = function () {
            return DashboardApp.postAssistantChat(payload).then(applyFinalReply);
        };

        const streamPromise = DashboardApp.streamAssistantChat(payload, {
            onStart: function (evt) {
                if (!live) {
                    live = appendLiveAssistantMsg();
                }
                if (evt && typeof evt.session_id === 'string' && evt.session_id) {
                    DashboardApp._assistantSessionId = evt.session_id;
                }
                if (budgetHintEl && evt) {
                    budgetHintEl.textContent = formatBudgetHint(evt.system_budget_chars);
                }
            },
            onDelta: function (evt) {
                if (!evt || typeof evt.content !== 'string' || !evt.content || !live) {
                    return;
                }
                // ``channel`` may be "thinking" (reasoning stream) or "content"
                // (visible answer). Older backends omit it — default to content.
                const ch = typeof evt.channel === 'string' ? evt.channel : 'content';
                live.appendText(evt.content, ch);
            },
            onError: function (evt) {
                streamingErrorShown = true;
                const errField = evt && evt.error;
                const detail =
                    typeof errField === 'string' && errField
                        ? errField
                        : errField &&
                            typeof errField === 'object' &&
                            typeof errField.message === 'string'
                          ? errField.message
                          : 'assistant stream error';
                if (live) {
                    live.remove();
                    live = null;
                }
                appendAssistantMsg({
                    message:
                        txt('streamErrorBeforeRetry', 'Streaming error: ') +
                        detail +
                        ' ' +
                        txt(
                            'streamRetryHint',
                            '(retrying with non-streaming request…)'
                        ),
                });
            },
        });

        streamPromise
            .then(applyFinalReply)
            .catch(function () {
                return runNonStreamingFallback().catch(applyError);
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

            const seedFromReport = reportMn ? String(reportMn).trim() : '';
            applyAssistantChatModelSeed(sorted, seedFromReport);
            activeChatModel =
                chatModelSelect && chatModelSelect.value ? String(chatModelSelect.value).trim() : '';
            const hadStoredChatModel = Boolean(getValidStoredChatModel(sorted));

            if (rows.length > 0) {
                const firstId = rows[0].session_id;
                populateSessionSelect(rows, firstId);
                return loadSessionById(firstId, {
                    useReportModelIfNoStored: !hadStoredChatModel,
                }).then(function () {
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
