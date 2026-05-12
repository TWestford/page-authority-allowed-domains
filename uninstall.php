<?php
/**
 * Uninstall cleanup for PA Allowed Email Domains.
 *
 * Developed and maintained by Talisa at Page Authority.
 * https://pageauthority.com/
 *
 * @package PA_Allowed_Email_Domains
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Remove single-site options.
 */
delete_option('paaed_allowed_domains');
delete_option('paaed_audit_log');

/**
 * Remove network-level options for multisite installations.
 */
if (is_multisite()) {
    delete_site_option('paaed_allowed_domains');
    delete_site_option('paaed_audit_log');
}
