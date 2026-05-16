<?php
/**
 * Uninstall cleanup for Page Authority - Allowed Domains.
 *
 * Developed and maintained by Talisa @ Page Authority.
 * https://pageauthority.com/
 *
 * @package Page_Authority_Allowed_Domains
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Keys to remove. Covers the current `pageauth_` prefix and every legacy
 * prefix from prior plugin versions (`aed_`, `paad_`, plus the never-written
 * `paaed_` referenced by an even older uninstall.php), so uninstall is clean
 * regardless of which version was last installed.
 */
$pageauth_option_keys = [
    // current — 2.0.0+
    'pageauth_allowed_domains',
    'pageauth_audit_log',
    'pageauth_block_unauthorized_logins',
    'pageauth_do_activation_redirect',
    'pageauth_migration_v200_complete',

    // legacy — 1.9.1
    'paad_allowed_domains',
    'paad_audit_log',
    'paad_block_unauthorized_logins',
    'paad_do_activation_redirect',
    'paad_migration_v191_complete',

    // legacy — 1.8.x / 1.9.0
    'aed_allowed_domains',
    'aed_audit_log',
    'aed_block_unauthorized_logins',
    'aed_do_activation_redirect',

    // historical bug — listed in an older uninstall.php but never written by the plugin
    'paaed_allowed_domains',
    'paaed_audit_log',
];

$pageauth_transients = [
    'pageauth_existing_user_audit_cache',
    'paad_existing_user_audit_cache',
    'aed_existing_user_audit_cache',
];

foreach ($pageauth_option_keys as $pageauth_key) {
    delete_option($pageauth_key);
}

foreach ($pageauth_transients as $pageauth_transient) {
    delete_transient($pageauth_transient);
}

if (is_multisite()) {
    foreach ($pageauth_option_keys as $pageauth_key) {
        delete_site_option($pageauth_key);
    }
    foreach ($pageauth_transients as $pageauth_transient) {
        delete_site_transient($pageauth_transient);
    }
}

// Also remove legacy user meta from the after-save audit fallback under prior prefixes.
delete_metadata('user', 0, '_pageauth_unauthorized_domain_detected', '', true);
delete_metadata('user', 0, '_paad_unauthorized_domain_detected', '', true);
delete_metadata('user', 0, '_aed_unauthorized_domain_detected', '', true);

unset($pageauth_option_keys, $pageauth_transients, $pageauth_key, $pageauth_transient);
