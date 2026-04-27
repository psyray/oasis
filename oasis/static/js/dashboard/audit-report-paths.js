/**
 * Canonical audit report artifact naming and JSON sibling resolution.
 * Aligned with oasis/export/filenames.AUDIT_REPORT_ARTIFACT_STEM and
 * oasis/helpers/dashboard/json_sibling.json_sibling_for_format_artifact.
 */
window.DashboardApp = window.DashboardApp || {};

/** @const {string} */
DashboardApp.AUDIT_REPORT_ARTIFACT_STEM = 'audit_report';

/**
 * Given a dashboard relative path to the audit markdown artifact, return the
 * sibling canonical JSON path, or null if the path is not ``.../md/<stem>.md``.
 *
 * @param {string} mdPath
 * @returns {string|null}
 */
DashboardApp.auditReportJsonSiblingPath = function (mdPath) {
    const stem = DashboardApp.AUDIT_REPORT_ARTIFACT_STEM;
    const p = String(mdPath || '');
    const esc = stem.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (!new RegExp('/md/' + esc + '\\.md$', 'i').test(p)) {
        return null;
    }
    return p.replace(/\/md\//i, '/json/').replace(
        new RegExp(stem + '\\.md$', 'i'),
        stem + '.json'
    );
};
