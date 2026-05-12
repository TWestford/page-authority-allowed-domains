<?php
/**
 * Plugin Name: Page Authority - Allowed Domains
 * Description: Restricts WordPress user emails to an administrator-managed allowlist of approved domains.
 * Version:     1.8.9
 * Requires PHP: 7.4
 * Tested up to: 6.9.4
 * Requires at least: 6.0
 * Author:      Talisa
 * License:     GPL-2.0-or-later
 * Text Domain: allowed-email-domains
 * @package Allowed_Email_Domains
 * */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/**
 * Stores the administrator-managed list of allowed email domains.
 *
 * Each saved value should be normalized in the format "@example.com".
 */
define('AED_OPTION_KEY', 'aed_allowed_domains');

/**
 * Stores the lightweight audit trail for allowlist changes.
 *
 * This plugin stores only the latest 25 entries to avoid unnecessary database
 * growth on long-running sites.
 */
define('AED_LOG_KEY', 'aed_audit_log');

/**
 * Transient key for cached Existing User Audit results.
 *
 * The cache stores display/reporting data only. Permissions, nonce checks,
 * add-domain actions, delete actions, and login enforcement are always
 * evaluated live.
 */
define('AED_AUDIT_CACHE_KEY', 'aed_existing_user_audit_cache');

/**
 * Audit cache duration in seconds.
 */
define('AED_AUDIT_CACHE_TTL', 5 * MINUTE_IN_SECONDS);

/**
 * Stores whether login blocking is enabled.
 *
 * Default is disabled to prevent accidental lockouts on existing sites.
 */
define('AED_LOGIN_BLOCK_OPTION_KEY', 'aed_block_unauthorized_logins');

/**
 * ============================================================================
 * OPTION HELPERS
 * ============================================================================
 */

/**
 * Determine whether this site should use network-level options.
 *
 * The plugin page is available to Super Admins on multisite. This helper keeps
 * option reads/writes consistent across single-site and multisite installs.
 *
 * @return bool
 */
function aed_use_network_options() {
    return is_multisite();
}

/**
 * Retrieve a plugin option from the correct option table.
 *
 * @param string $key     Option key.
 * @param mixed  $default Default value.
 * @return mixed
 */
function aed_get_option($key, $default = false) {
    if (aed_use_network_options()) {
        return get_site_option($key, $default);
    }

    return get_option($key, $default);
}

/**
 * Update a plugin option in the correct option table.
 *
 * @param string $key   Option key.
 * @param mixed  $value Option value.
 * @return bool
 */
function aed_update_option($key, $value) {
    if (aed_use_network_options()) {
        return update_site_option($key, $value);
    }

    return update_option($key, $value);
}

/**
 * Delete a plugin option from the correct option table.
 *
 * @param string $key Option key.
 * @return bool
 */
function aed_delete_option($key) {
    if (aed_use_network_options()) {
        return delete_site_option($key);
    }

    return delete_option($key);
}

/**
 * ============================================================================
 * DOMAIN NORMALIZATION + VALIDATION
 * ============================================================================
 */

/**
 * Normalize and validate an allowlist domain entry.
 *
 * Admins may type either "example.com" or "@example.com"; both are normalized to
 * "@example.com". The leading "@" is intentionally stored because it makes the
 * match exact against an email suffix and prevents partial-domain confusion.
 *
 * Valid examples:
 * - @example.com
 * - @example.org
 * - @example.co.uk
 *
 * Rejected examples:
 * - @example
 * - @example.
 * - @.com
 * - example
 *
 * @param string $domain Raw domain string.
 * @return string|false Normalized domain or false when invalid.
 */
function aed_normalize_domain($domain) {
    $domain = strtolower(trim((string) $domain));

    if ($domain === '') {
        return false;
    }

    if ($domain[0] !== '@') {
        $domain = '@' . ltrim($domain, '@');
    }

    $domain_without_at = substr($domain, 1);

    /**
     * Validate the domain by placing it into a synthetic email address.
     * This catches malformed domain strings without maintaining a fragile custom
     * regular expression for every possible valid TLD pattern.
     */
    if (!filter_var('test' . $domain, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    /**
     * Require at least one suffix/TLD segment.
     * This allows .com, .org, .edu, .co.uk, etc. while rejecting "@example".
     */
    if (!preg_match('/\.[a-z]{2,}$/i', $domain_without_at)) {
        return false;
    }

    return $domain;
}

/**
 * Extract a normalized "@domain.tld" suffix from an email address.
 *
 * @param string $email Email address.
 * @return string Empty string when email format is invalid.
 */
function aed_get_email_domain($email) {
    $parts = explode('@', strtolower(trim((string) $email)));

    if (count($parts) !== 2 || $parts[1] === '') {
        return '';
    }

    return '@' . $parts[1];
}

/**
 * Return the configured allowlist.
 *
 * @return array<int,string>
 */
function aed_get_allowed_domains() {
    $domains = aed_get_option(AED_OPTION_KEY, []);

    if (!is_array($domains)) {
        return [];
    }

    return array_values(array_unique(array_filter($domains)));
}

/**
 * Empty allowlist behavior.
 *
 * Important deployment decision:
 * An empty allowlist means all email domains are allowed. This prevents accidental
 * lockouts across multi-site rollouts and allows a plugin to be installed before
 * each client/site-specific allowlist is configured.
 *
 * @return bool
 */
function aed_allowlist_is_empty() {
    return empty(aed_get_allowed_domains());
}

/**
 * Check whether an email address is allowed by the current allowlist.
 *
 * @param string $email Email address.
 * @return bool
 */

/**
 * Check whether login blocking is enabled.
 *
 * Default is OFF. This prevents accidental lockouts when an allowlist is first
 * introduced on a site that already has users outside the approved domains.
 *
 * @return bool
 */
function aed_login_blocking_enabled() {
    return (bool) aed_get_option(AED_LOGIN_BLOCK_OPTION_KEY, false);
}

function aed_is_email_allowed($email) {
    if (aed_allowlist_is_empty()) {
        return true;
    }

    $domain = aed_get_email_domain($email);

    return in_array($domain, aed_get_allowed_domains(), true);
}

/**
 * ============================================================================
 * USER CREATION + UPDATE ENFORCEMENT
 * ============================================================================
 */

/**
 * Block disallowed email domains during standard WordPress registration.
 *
 * This covers the normal wp-login.php?action=register flow.
 */
add_filter(
    'registration_errors',
    function ($errors, $sanitized_user_login, $user_email) {
        if (!aed_is_email_allowed($user_email)) {
            $errors->add(
                'aed_invalid_domain',
                __('Registration is limited to approved email domains.', 'allowed-email-domains')
            );
        }

        return $errors;
    },
    10,
    3
);


/**
 * Show inline admin errors on Add New User / Edit User screens.
 *
 * This prevents WordPress Admin from redirecting to a plain wp_die() page when
 * an administrator enters a disallowed email address. The error appears in the
 * normal WordPress admin notice area, similar to native password/email errors.
 */
add_action(
    'user_profile_update_errors',
    function ($errors, $update, $user) {

        if (empty($user->user_email) || aed_is_email_allowed($user->user_email)) {
            return;
        }

        $domain = aed_get_email_domain($user->user_email);
        $settings_url = aed_get_settings_url();

        $message = sprintf(
            '<div class="aed-admin-error-box">' .
                '<p class="aed-admin-error-title">%s</p>' .
                '<p>%s</p>' .
                '<p><strong>%s</strong></p>' .
                '<ol>' .
                    '<li>%s</li>' .
                    '<li>%s</li>' .
                    '<li>%s</li>' .
                '</ol>' .
                '<p>%s</p>' .
            '</div>',
            esc_html__('This email domain is not approved for user accounts on this site.', 'allowed-email-domains'),
            sprintf(
                /* translators: %s: Email domain. */
                esc_html__('The domain "%s" is not on the list of allowed domains.', 'allowed-email-domains'),
                esc_html(ltrim($domain, '@'))
            ),
            esc_html__('How to fix this:', 'allowed-email-domains'),
            sprintf(
                wp_kses(
                    /* translators: %s: URL to the Allowed Domains settings page. */
                    __('Go to <a href="%s">Users → Allowed Domains</a>.', 'allowed-email-domains'),
                    ['a' => ['href' => []]]
                ),
                esc_url($settings_url)
            ),
            esc_html__('Add this domain (or the correct domain) to the allowed list.', 'allowed-email-domains'),
            esc_html__('Save your changes and try again.', 'allowed-email-domains'),
            esc_html__('Need help? Contact your site administrator.', 'allowed-email-domains')
        );

        $errors->add('aed_invalid_domain', $message);
    },
    10,
    3
);


/**
 * Block disallowed email domains during programmatic user insert/update calls.
 *
 * This is the broader enforcement layer. It catches many plugin-driven flows
 * that bypass the standard registration form and call wp_insert_user() directly.
 */
add_filter(
    'wp_pre_insert_user_data',
    function ($data, $update, $user_id, $userdata) {
        if (!empty($data['user_email']) && !aed_is_email_allowed($data['user_email'])) {

            /*
             * The WordPress admin Add/Edit User screens are handled by
             * user_profile_update_errors above so admins see a normal inline
             * error instead of a full-page wp_die() message.
             */
            if (is_admin()) {
                return $data;
            }

            wp_die(
                esc_html__('This email domain is not approved for user accounts on this site.', 'allowed-email-domains'),
                esc_html__('Email Domain Restricted', 'allowed-email-domains'),
                ['response' => 403]
            );
        }

        return $data;
    },
    10,
    4
);


/**
 * Print disclaimer below admin email fields.
 */
function aed_print_email_disclaimer() {
    $settings_url = aed_get_settings_url();
    ?>
    <style>
        .aed-email-disclaimer {
            display:block;
            max-width:580px;
            margin:4px 0 0;
            padding:6px 8px;
            border-left:4px solid #d63638;
            background:#fff5f5;
            color:#8a2424;
            font-size:12px;
            line-height:1.45;
        }
    </style>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        var emailField = document.getElementById('email');

        if (!emailField || document.getElementById('aed-email-disclaimer')) {
            return;
        }

        var disclaimer = document.createElement('p');
        disclaimer.id = 'aed-email-disclaimer';
        disclaimer.className = 'description aed-email-disclaimer';
        disclaimer.innerHTML = <?php echo wp_json_encode(
            sprintf(
                wp_kses(
                    /* translators: %s: URL to the Allowed Domains settings page. */
                        __('Only approved domains can be used for user accounts. Manage the allowlist under <a href="%s">Users → Allowed Domains</a>.', 'allowed-email-domains'),
                    ['a' => ['href' => []]]
                ),
                esc_url($settings_url)
            )
        ); ?>;

        emailField.insertAdjacentElement('afterend', disclaimer);
    });
    </script>
    <?php
}
add_action('admin_head-user-new.php', 'aed_print_email_disclaimer');
add_action('admin_head-user-edit.php', 'aed_print_email_disclaimer');
add_action('admin_head-profile.php', 'aed_print_email_disclaimer');


/**
 * ============================================================================
 * ADMIN SETTINGS REGISTRATION
 * ============================================================================
 */

/**
 * Determine the required capability for managing the allowlist.
 *
 * Single site: manage_options
 * Multisite: manage_network_options
 *
 * @return string
 */

/**
 * Get the canonical plugin settings URL.
 *
 * @param array<string,string|int> $args Optional query args.
 * @param string                  $fragment Optional URL fragment without #.
 * @return string
 */
function aed_get_settings_url($args = [], $fragment = '') {
    $url = add_query_arg(
        array_merge(
            ['page' => 'aed-settings'],
            $args
        ),
        admin_url('users.php')
    );

    if ($fragment !== '') {
        $url .= '#' . ltrim($fragment, '#');
    }

    return $url;
}


function aed_manage_capability() {
    return is_multisite() ? 'manage_network_options' : 'manage_options';
}

/**
 * Register the Users submenu page.
 */
add_action(
    'admin_menu',
    function () {
        add_users_page(
            __('Allowed Domains', 'allowed-email-domains'),
            __('Allowed Domains', 'allowed-email-domains'),
            aed_manage_capability(),
            'aed-settings',
            'aed_render_settings_page'
        );
    }
);

/**
 * Handle settings form submission manually.
 *
 * This avoids edge cases with network options and keeps nonce/capability checks
 * explicit in one place.
 */
add_action(
    'admin_init',
    function () {
        $action = filter_input(INPUT_POST, 'aed_action', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        if ($action !== 'save_domains') {
            return;
        }

        if (!current_user_can(aed_manage_capability())) {
            wp_die(esc_html__('You do not have permission to manage allowed email domains.', 'allowed-email-domains'));
        }

        check_admin_referer('aed_save_domains');

        $raw_domains = isset($_POST[AED_OPTION_KEY]) ? sanitize_textarea_field(wp_unslash($_POST[AED_OPTION_KEY])) : '';
        $clean_domains = aed_sanitize_domains($raw_domains);

        aed_update_option(AED_OPTION_KEY, $clean_domains);
        aed_log_change($clean_domains);
        aed_clear_audit_cache();

        wp_safe_redirect(
            add_query_arg(
                [
                    'page' => 'aed-settings',
                    'updated' => 'true',
                ],
                admin_url('users.php')
            )
        );
        exit;
    }
);

/**
 * Sanitize textarea input into a unique list of normalized domains.
 *
 * Invalid lines are ignored rather than saved.
 *
 * @param string $input Raw textarea input.
 * @return array<int,string>
 */
function aed_sanitize_domains($input) {
    $lines = preg_split('/\r\n|\r|\n/', (string) $input);
    $clean = [];

    foreach ($lines as $line) {
        $domain = aed_normalize_domain($line);

        if ($domain !== false) {
            $clean[] = $domain;
        }
    }

    return array_values(array_unique($clean));
}

/**
 * ============================================================================
 * AUDIT LOGGING
 * ============================================================================
 */

/**
 * Store a lightweight audit log of allowlist changes.
 *
 * This is intentionally simple. It records:
 * - timestamp
 * - admin username
 * - saved domains
 *
 * @param array<int,string> $domains Saved domains.
 * @return void
 */
function aed_log_change($domains) {
    $logs = aed_get_option(AED_LOG_KEY, []);

    if (!is_array($logs)) {
        $logs = [];
    }

    $current_user = wp_get_current_user();

    $logs[] = [
        'time'    => current_time('mysql'),
        'user'    => $current_user && $current_user->exists() ? $current_user->user_login : 'unknown',
        'domains' => $domains,
    ];

    $logs = array_slice($logs, -25);

    aed_update_option(AED_LOG_KEY, $logs);
}



/**
 * ============================================================================
 * BROADER REGISTRATION FLOW ENFORCEMENT
 * ============================================================================
 */

/**
 * Enforce allowed domains for REST API user creation/update.
 *
 * This covers integrations and custom admin tools that create users through the
 * WordPress REST API.
 */
add_filter(
    'rest_pre_insert_user',
    function ($prepared_user, $request, $creating) {
        if (!empty($prepared_user->user_email) && !aed_is_email_allowed($prepared_user->user_email)) {
            return new WP_Error(
                'aed_invalid_domain',
                __('This email domain is not approved for user accounts on this site.', 'allowed-email-domains'),
                ['status' => 403]
            );
        }

        return $prepared_user;
    },
    10,
    3
);

/**
 * Enforce allowed domains for WooCommerce registration, when WooCommerce exists.
 *
 * The filter is harmless on sites without WooCommerce because WordPress allows
 * filters to be registered even when the emitting plugin is inactive.
 */
add_filter(
    'woocommerce_registration_errors',
    function ($errors, $username, $email) {
        if (!aed_is_email_allowed($email)) {
            $errors->add(
                'aed_invalid_domain',
                __('This email domain is not approved for user accounts on this site. Please use an approved email address or contact the site administrator.', 'allowed-email-domains')
            );
        }

        return $errors;
    },
    10,
    3
);

/**
 * After-save audit fallback.
 *
 * Some plugins may bypass the normal registration error hooks but still rely on
 * WordPress user APIs. This fallback flags users that exist after creation/update
 * without deleting or disabling them. The Existing User Audit and admin notice
 * will surface them for review.
 */
function aed_after_user_save_audit_fallback($user_id) {
    $user = get_userdata($user_id);

    if (!$user || empty($user->user_email)) {
        return;
    }

    if (aed_is_email_allowed($user->user_email)) {
        delete_user_meta($user_id, '_aed_unauthorized_domain_detected');
        aed_clear_audit_cache();
        return;
    }

    update_user_meta($user_id, '_aed_unauthorized_domain_detected', current_time('mysql'));
    aed_clear_audit_cache();
}
add_action('user_register', 'aed_after_user_save_audit_fallback', 20);
add_action('profile_update', 'aed_after_user_save_audit_fallback', 20);

/**
 * Optional login-time enforcement.
 *
 * Disabled by default. When enabled, users with email domains outside the
 * allowlist cannot log in. Keep disabled until the audit report has been reviewed
 * to avoid locking out legitimate existing admins.
 */
add_filter(
    'authenticate',
    function ($user, $username, $password) {
        if (!aed_login_blocking_enabled()) {
            return $user;
        }

        if (aed_allowlist_is_empty()) {
            return $user;
        }

        if (is_wp_error($user) || !$user instanceof WP_User) {
            return $user;
        }

        if (!aed_is_email_allowed($user->user_email)) {
            return new WP_Error(
                'aed_login_blocked',
                __('Your account email domain is not currently approved for this site. Please contact the site administrator.', 'allowed-email-domains')
            );
        }

        return $user;
    },
    30,
    3
);



/**
 * Handle login-blocking setting changes.
 */
function aed_handle_login_blocking_setting() {
    if (empty($_POST['aed_action']) || $_POST['aed_action'] !== 'save_login_blocking') {
        return;
    }

    if (!current_user_can(aed_manage_capability())) {
        wp_die(esc_html__('You do not have permission to manage login enforcement.', 'allowed-email-domains'));
    }

    check_admin_referer('aed_save_login_blocking');

    $enabled = !empty($_POST[AED_LOGIN_BLOCK_OPTION_KEY]) ? 1 : 0;

    aed_update_option(AED_LOGIN_BLOCK_OPTION_KEY, $enabled);

    wp_safe_redirect(
        add_query_arg(
            [
                'page' => 'aed-settings',
                'aed_login_blocking_updated' => 'true',
            ],
            admin_url('users.php')
        )
    );
    exit;
}
add_action('admin_init', 'aed_handle_login_blocking_setting');


/**
 * ============================================================================
 * EXISTING USER AUDIT
 * ============================================================================
 */

/**
 * Find existing users whose email domains are not currently allowed.
 *
 * This is audit-only. It does not delete, disable, modify, or log out users.
 * Empty allowlist means all domains are allowed, so no users are flagged.
 *
 * @return array<int,array<string,string>>
 */

/**
 * Clear the Existing User Audit cache.
 *
 * Call this whenever allowlist data or user email/domain state may have changed.
 *
 * @return void
 */
function aed_clear_audit_cache() {
    delete_transient(AED_AUDIT_CACHE_KEY);
}

/**
 * Build Existing User Audit results live from the users table.
 *
 * This function intentionally performs no destructive action. It only creates
 * display data for the audit report and admin notice.
 *
 * @return array<int,array<string,string>>
 */
function aed_build_unauthorized_existing_users_audit() {
    if (aed_allowlist_is_empty()) {
        return [];
    }

    $users = get_users(
        [
            'fields' => ['ID', 'user_login', 'user_email', 'display_name'],
            'number' => -1,
        ]
    );

    $flagged = [];

    foreach ($users as $user) {
        if (!aed_is_email_allowed($user->user_email)) {
            $flagged[] = [
                'id'           => (string) $user->ID,
                'user_login'   => (string) $user->user_login,
                'display_name' => (string) $user->display_name,
                'user_email'   => (string) $user->user_email,
                'domain'       => aed_get_email_domain($user->user_email),
            ];
        }
    }

    return $flagged;
}


function aed_get_unauthorized_existing_users() {
    if (aed_allowlist_is_empty()) {
        aed_clear_audit_cache();
        return [];
    }

    $cached = get_transient(AED_AUDIT_CACHE_KEY);

    if (is_array($cached)) {
        return $cached;
    }

    $flagged = aed_build_unauthorized_existing_users_audit();

    set_transient(AED_AUDIT_CACHE_KEY, $flagged, AED_AUDIT_CACHE_TTL);

    return $flagged;
}

/**
 * Display an admin notice when unauthorized existing users are found.
 *
 * This notice is audit-only and links to the full report.
 *
 * @return void
 */
function aed_show_unauthorized_users_admin_notice() {
    if (!current_user_can(aed_manage_capability())) {
        return;
    }

    if (aed_allowlist_is_empty()) {
        return;
    }

    $screen = function_exists('get_current_screen') ? get_current_screen() : null;

    if ($screen && $screen->id === 'users_page_aed-settings') {
        return;
    }

    $flagged = aed_get_unauthorized_existing_users();

    if (empty($flagged)) {
        return;
    }

    $report_url = aed_get_settings_url([], 'aed-existing-user-audit');
    ?>
    <div class="notice notice-warning">
        <p>
            <strong><?php esc_html_e('Allowed Email Domains audit warning:', 'allowed-email-domains'); ?></strong>
            <?php
            printf(
                esc_html(
                    /* translators: %d: Number of existing users with unauthorized email domains. */
                    _n(
                        '%d existing user has an email domain that is not currently allowed.',
                        '%d existing users have email domains that are not currently allowed.',
                        count($flagged),
                        'allowed-email-domains'
                    )
                ),
                count($flagged)
            );
            ?>
            <a href="<?php echo esc_url($report_url); ?>">
                <?php esc_html_e('Review the audit report.', 'allowed-email-domains'); ?>
            </a>
        </p>
    </div>
    <?php
}
add_action('admin_notices', 'aed_show_unauthorized_users_admin_notice');



/**
 * Delete one unauthorized user from the Existing User Audit.
 *
 * This action is protected by:
 * - capability check
 * - nonce verification
 * - current-user exclusion
 * - multisite Super Admin exclusion
 * - revalidation that the selected user is still unauthorized
 *
 * @return void
 */
function aed_handle_delete_unauthorized_user() {
    $action = filter_input(INPUT_GET, 'aed_action', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    if ($action !== 'delete_unauthorized_user') {
        return;
    }

    if (!current_user_can(aed_manage_capability())) {
        wp_die(esc_html__('You do not have permission to delete users.', 'allowed-email-domains'));
    }

    $user_id = absint(filter_input(INPUT_GET, 'user_id', FILTER_SANITIZE_NUMBER_INT));

    if (!$user_id) {
        wp_safe_redirect(
            add_query_arg(
                [
                    'page' => 'aed-settings',
                    'aed_delete_error' => 'missing_user',
                ],
                admin_url('users.php')
            )
        );
        exit;
    }

    check_admin_referer('aed_delete_unauthorized_user_' . $user_id);

    if ($user_id === get_current_user_id()) {
        wp_safe_redirect(
            add_query_arg(
                [
                    'page' => 'aed-settings',
                    'aed_delete_error' => 'current_user',
                ],
                admin_url('users.php')
            )
        );
        exit;
    }

    if (is_multisite() && is_super_admin($user_id)) {
        wp_safe_redirect(
            add_query_arg(
                [
                    'page' => 'aed-settings',
                    'aed_delete_error' => 'super_admin',
                ],
                admin_url('users.php')
            )
        );
        exit;
    }

    $user = get_userdata($user_id);

    if (!$user) {
        wp_safe_redirect(
            add_query_arg(
                [
                    'page' => 'aed-settings',
                    'aed_delete_error' => 'not_found',
                ],
                admin_url('users.php')
            )
        );
        exit;
    }

    /*
     * Recheck the user's email before deletion. If the allowlist changed or the
     * user email was corrected, deletion is blocked.
     */
    if (aed_is_email_allowed($user->user_email)) {
        wp_safe_redirect(
            add_query_arg(
                [
                    'page' => 'aed-settings',
                    'aed_delete_error' => 'user_allowed',
                ],
                admin_url('users.php')
            )
        );
        exit;
    }

    if (!function_exists('wp_delete_user')) {
        require_once ABSPATH . 'wp-admin/includes/user.php';
    }

    $deleted = wp_delete_user($user_id);

    if ($deleted) {
        aed_clear_audit_cache();
    }

    wp_safe_redirect(
        add_query_arg(
            [
                'page' => 'aed-settings',
                'aed_deleted_user' => $deleted ? 1 : 0,
                'aed_deleted_id'   => $user_id,
            ],
            admin_url('users.php')
        )
    );
    exit;
}
add_action('admin_init', 'aed_handle_delete_unauthorized_user');




/**
 * Add a domain from the Existing User Audit directly to the allowlist.
 *
 * Uses admin-post.php instead of users.php?page=... so WordPress does not try
 * to authorize the request as a submenu page before the action handler runs.
 *
 * This action is protected by:
 * - capability check
 * - nonce verification
 * - domain normalization/validation
 *
 * After saving, the admin is redirected back to the audit section so the list
 * refreshes immediately with the updated allowlist.
 *
 * @return void
 */
function aed_handle_add_audit_domain_to_allowlist() {
    if (!current_user_can(aed_manage_capability())) {
        wp_die(esc_html__('You do not have permission to manage allowed domains.', 'allowed-email-domains'));
    }

    $domain = sanitize_text_field((string) filter_input(INPUT_GET, 'domain', FILTER_SANITIZE_FULL_SPECIAL_CHARS));
    $domain = aed_normalize_domain($domain);

    if (!$domain) {
        wp_safe_redirect(aed_get_settings_url(['aed_add_error' => 'invalid_domain'], 'aed-existing-user-audit'));
        exit;
    }

    check_admin_referer('aed_add_audit_domain_' . md5($domain));

    $domains = aed_get_allowed_domains();

    if (!in_array($domain, $domains, true)) {
        $domains[] = $domain;
        sort($domains);
        aed_update_option(AED_OPTION_KEY, array_values(array_unique($domains)));
        aed_log_change($domains);
        aed_clear_audit_cache();
    }

    wp_safe_redirect(aed_get_settings_url(['aed_added_domain' => rawurlencode($domain)], 'aed-existing-user-audit'));
    exit;
}
add_action('admin_post_aed_add_audit_domain', 'aed_handle_add_audit_domain_to_allowlist');




/**
 * Clear audit cache when user data changes outside this plugin.
 */
add_action('deleted_user', 'aed_clear_audit_cache');
add_action('profile_update', 'aed_clear_audit_cache', 99);
add_action('user_register', 'aed_clear_audit_cache', 99);


/**
 * ============================================================================
 * ADMIN SCREEN
 * ============================================================================
 */

/**
 * Render the settings page.
 *
 * @return void
 */
function aed_render_settings_page() {
    if (!current_user_can(aed_manage_capability())) {
        return;
    }

    $domains = implode("\n", aed_get_allowed_domains());
    $logs    = aed_get_option(AED_LOG_KEY, []);

    $aed_updated_notice = filter_input(INPUT_GET, 'updated', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $aed_added_domain_notice = filter_input(INPUT_GET, 'aed_added_domain', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $aed_add_error_notice = filter_input(INPUT_GET, 'aed_add_error', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $aed_login_blocking_updated_notice = filter_input(INPUT_GET, 'aed_login_blocking_updated', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $aed_deleted_user_notice = filter_input(INPUT_GET, 'aed_deleted_user', FILTER_SANITIZE_NUMBER_INT);
    $aed_delete_error_notice = filter_input(INPUT_GET, 'aed_delete_error', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

    ?>
    <div class="wrap">
        <h1><?php esc_html_e('Allowed Email Domains', 'allowed-email-domains'); ?></h1>

        <?php if (!empty($aed_updated_notice)) : ?>
            <div class="notice notice-success is-dismissible">
                <p><?php esc_html_e('Allowed email domains updated.', 'allowed-email-domains'); ?></p>
            </div>
        <?php endif; ?>

        <?php if (aed_allowlist_is_empty()) : ?>
            <div class="notice notice-warning">
                <p>
                    <?php esc_html_e('No domains are configured. All email domains are currently allowed.', 'allowed-email-domains'); ?>
                </p>
            </div>
        <?php endif; ?>

        <form method="post" action="">
            <?php wp_nonce_field('aed_save_domains'); ?>
            <input type="hidden" name="aed_action" value="save_domains">

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row">
                        <label for="<?php echo esc_attr(AED_OPTION_KEY); ?>">
                            <?php esc_html_e('Allowed Email Domains', 'allowed-email-domains'); ?>
                        </label>
                    </th>
                    <td>
                        <textarea
                            id="<?php echo esc_attr(AED_OPTION_KEY); ?>"
                            name="<?php echo esc_attr(AED_OPTION_KEY); ?>"
                            rows="10"
                            cols="50"
                            class="large-text code"
                            placeholder="@example.com&#10;@example.org&#10;@example.co.uk"
                        ><?php echo esc_textarea($domains); ?></textarea>

                        <p class="description">
                            <?php esc_html_e('One domain per line. Entries are normalized to start with "@". A valid suffix/TLD is required. Empty list allows all domains.', 'allowed-email-domains'); ?>
                        </p>
                    </td>
                </tr>
            </table>

            <?php submit_button(__('Save Domains', 'allowed-email-domains')); ?>
        </form>

        
        <hr>

        <h2><?php esc_html_e('Login Enforcement', 'allowed-email-domains'); ?></h2>

        <p>
            <?php esc_html_e('Optional login blocking prevents existing users with unauthorized email domains from signing in. Leave this disabled until you have reviewed the Existing User Audit to avoid accidental lockouts.', 'allowed-email-domains'); ?>
        </p>

        <form method="post" action="">
            <?php wp_nonce_field('aed_save_login_blocking'); ?>
            <input type="hidden" name="aed_action" value="save_login_blocking">

            <label>
                <input
                    type="checkbox"
                    name="<?php echo esc_attr(AED_LOGIN_BLOCK_OPTION_KEY); ?>"
                    value="1"
                    <?php checked(aed_login_blocking_enabled()); ?>
                >
                <?php esc_html_e('Block login for users whose email domain is not allowed', 'allowed-email-domains'); ?>
            </label>

            <?php submit_button(__('Save Login Enforcement Setting', 'allowed-email-domains')); ?>
        </form>

        <hr id="aed-existing-user-audit">

        <h2><?php esc_html_e('Existing User Audit', 'allowed-email-domains'); ?></h2>

        <p>
            <?php esc_html_e('This report flags existing users whose email domains are not currently on the allowed list. It is audit-only and does not disable, delete, or modify users.', 'allowed-email-domains'); ?>
        </p>

        <?php $unauthorized_users = aed_get_unauthorized_existing_users(); ?>

        <?php if (aed_allowlist_is_empty()) : ?>
            <div class="notice notice-info inline">
                <p><?php esc_html_e('No audit results are shown because the allowlist is empty and all domains are currently allowed.', 'allowed-email-domains'); ?></p>
            </div>
        <?php elseif (empty($unauthorized_users)) : ?>
            <div class="notice notice-success inline">
                <p><?php esc_html_e('No existing users with unauthorized email domains were found.', 'allowed-email-domains'); ?></p>
            </div>
        <?php else : ?>
            <div class="notice notice-warning inline">
                <p>
                    <strong><?php esc_html_e('Action recommended:', 'allowed-email-domains'); ?></strong>
                    <?php esc_html_e('Review these users, update their email addresses, add the appropriate domains to the allowlist, or delete individual unauthorized users.', 'allowed-email-domains'); ?>
                </p>
            </div>

            <table class="widefat striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e('User', 'allowed-email-domains'); ?></th>
                        <th><?php esc_html_e('Username', 'allowed-email-domains'); ?></th>
                        <th><?php esc_html_e('Email', 'allowed-email-domains'); ?></th>
                        <th><?php esc_html_e('Domain', 'allowed-email-domains'); ?></th>
                        <th><?php esc_html_e('Action', 'allowed-email-domains'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($unauthorized_users as $audit_user) : ?>
                        <tr>
                            <td><?php echo esc_html($audit_user['display_name']); ?></td>
                            <td><?php echo esc_html($audit_user['user_login']); ?></td>
                            <td><?php echo esc_html($audit_user['user_email']); ?></td>
                            <td><?php echo esc_html($audit_user['domain']); ?></td>
                            <td>
                                <a href="<?php echo esc_url(get_edit_user_link((int) $audit_user['id'])); ?>">
                                    <?php esc_html_e('Edit user', 'allowed-email-domains'); ?>
                                </a>
                                |
                                <?php
                                $add_domain_url = wp_nonce_url(
                                    add_query_arg(
                                        [
                                            'action' => 'aed_add_audit_domain',
                                            'domain' => $audit_user['domain'],
                                        ],
                                        admin_url('admin-post.php')
                                    ),
                                    'aed_add_audit_domain_' . md5($audit_user['domain'])
                                );
                                ?>
                                <a href="<?php echo esc_url($add_domain_url); ?>">
                                    <?php esc_html_e('Add domain', 'allowed-email-domains'); ?>
                                </a>
                                |
                                <?php
                                $delete_url = wp_nonce_url(
                                    add_query_arg(
                                        [
                                            'page' => 'aed-settings',
                                            'aed_action' => 'delete_unauthorized_user',
                                            'user_id'    => (int) $audit_user['id'],
                                        ],
                                        admin_url('users.php')
                                    ),
                                    'aed_delete_unauthorized_user_' . (int) $audit_user['id']
                                );
                                ?>
                                <a
                                    href="<?php echo esc_url($delete_url); ?>"
                                    class="submitdelete"
                                    onclick="return confirm('<?php echo esc_js(__('Delete this unauthorized user? This cannot be undone.', 'allowed-email-domains')); ?>');"
                                >
                                    <?php esc_html_e('Delete user', 'allowed-email-domains'); ?>
                                </a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>


        <hr>

        <h2><?php esc_html_e('Recent Allowlist Changes', 'allowed-email-domains'); ?></h2>

        <table class="widefat striped">
            <thead>
                <tr>
                    <th><?php esc_html_e('Timestamp', 'allowed-email-domains'); ?></th>
                    <th><?php esc_html_e('Admin', 'allowed-email-domains'); ?></th>
                    <th><?php esc_html_e('Domains', 'allowed-email-domains'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (!empty($logs) && is_array($logs)) : ?>
                    <?php foreach (array_reverse($logs) as $log) : ?>
                        <tr>
                            <td><?php echo esc_html(isset($log['time']) ? $log['time'] : ''); ?></td>
                            <td><?php echo esc_html(isset($log['user']) ? $log['user'] : ''); ?></td>
                            <td>
                                <?php
                                $log_domains = isset($log['domains']) && is_array($log['domains']) ? $log['domains'] : [];
                                echo esc_html(implode(', ', $log_domains));
                                ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php else : ?>
                    <tr>
                        <td colspan="3"><?php esc_html_e('No changes logged yet.', 'allowed-email-domains'); ?></td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
    <?php
}



/**
 * Add quick plugin action links on the Plugins screen.
 *
 * Adds:
 * - Settings
 * - README
 *
 * This improves admin navigation and provides quick access to plugin
 * documentation directly from the Plugins page.
 *
 * @param array $links Existing plugin action links.
 * @return array
 */
function aed_plugin_action_links($links) {

    $settings_link =
        '<a href="' .
        esc_url(admin_url('users.php?page=aed-settings')) .
        '">' .
        esc_html__('Settings', 'allowed-email-domains') .
        '</a>';

    array_unshift($links, $settings_link);

    return $links;
}

add_filter(
    'plugin_action_links_' . plugin_basename(__FILE__),
    'aed_plugin_action_links'
);











/**
 * Redirect admins to the Allowed Domains settings page after activation.
 *
 * This improves onboarding by taking administrators directly to the
 * configuration screen immediately after activation.
 */

/**
 * Store activation redirect flag.
 *
 * @return void
 */
function aed_activation_redirect_flag() {

    if (!current_user_can(aed_manage_capability())) {
        return;
    }

    add_option('aed_do_activation_redirect', 1);
}

register_activation_hook(__FILE__, 'aed_activation_redirect_flag');

/**
 * Perform post-activation redirect.
 *
 * Skips:
 * - bulk activations
 * - users without permission
 *
 * @return void
 */
function aed_do_activation_redirect() {

    if (!get_option('aed_do_activation_redirect')) {
        return;
    }

    delete_option('aed_do_activation_redirect');

    if (wp_doing_ajax()) {
        return;
    }

    if (!current_user_can(aed_manage_capability())) {
        return;
    }

    $activate_multi = filter_input(INPUT_GET, 'activate-multi', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    if ($activate_multi !== null) {
        return;
    }

    wp_safe_redirect(
        admin_url('users.php?page=aed-settings')
    );

    exit;
}

add_action('admin_init', 'aed_do_activation_redirect');

/**
 * Add update success redirect helper.
 *
 * After plugin updates, admins can quickly return to the settings page from
 * the Plugins screen using the existing Settings quick link.
 *
 * WordPress does not provide a reliable native post-update redirect hook for
 * standard plugin upgrades, so activation redirects are intentionally limited
 * to first-time activation only.
 */

