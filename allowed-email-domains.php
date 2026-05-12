<?php
/**
 * Plugin Name: Page Authority - Allowed Domains
 * Description: Restricts WordPress user emails to an administrator-managed allowlist of approved domains.
 * Version: 1.9.0
 * Requires at least: 6.0
 * Tested up to: 6.9
 * Requires PHP: 7.4
 * Author: Talisa
 * Author URI: https://pageauthority.com/
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: page-authority-allowed-domains
 */

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
 * Batch size for paginated user queries.
 *
 * Used by the Existing User Audit and the reassignment dropdown helper to
 * avoid loading every user into memory on large installations.
 */
define('AED_USER_QUERY_BATCH_SIZE', 500);

/**
 * Maximum number of compliant users returned for the reassignment dropdown.
 *
 * Keeps the modal usable on large sites. If a site has more eligible users
 * than this, only the first set is returned and the admin is informed.
 */
define('AED_REASSIGN_DROPDOWN_LIMIT', 500);

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

/**
 * Check whether an email address is allowed by the current allowlist.
 *
 * @param string $email Email address.
 * @return bool
 */
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
                __('Registration is limited to approved email domains.', 'page-authority-allowed-domains')
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
            esc_html__('This email domain is not approved for user accounts on this site.', 'page-authority-allowed-domains'),
            sprintf(
                /* translators: %s: Email domain. */
                esc_html__('The domain "%s" is not on the list of allowed domains.', 'page-authority-allowed-domains'),
                esc_html(ltrim($domain, '@'))
            ),
            esc_html__('How to fix this:', 'page-authority-allowed-domains'),
            sprintf(
                wp_kses(
                    /* translators: %s: URL to the Allowed Domains settings page. */
                    __('Go to <a href="%s">Users → Allowed Domains</a>.', 'page-authority-allowed-domains'),
                    ['a' => ['href' => []]]
                ),
                esc_url($settings_url)
            ),
            esc_html__('Add this domain (or the correct domain) to the allowed list.', 'page-authority-allowed-domains'),
            esc_html__('Save your changes and try again.', 'page-authority-allowed-domains'),
            esc_html__('Need help? Contact your site administrator.', 'page-authority-allowed-domains')
        );

        $errors->add('aed_invalid_domain', $message);
    },
    10,
    3
);


/**
 * Return the set of admin screen IDs that fire user_profile_update_errors.
 *
 * On those screens the inline error path in user_profile_update_errors handles
 * the unauthorized-domain case and renders a normal WP admin notice. Everywhere
 * else (admin AJAX, importers, REST handlers running in admin context, custom
 * registration flows) gets a wp_die() so the user is never silently created.
 *
 * @return array<int,string>
 */
function aed_inline_error_admin_screens() {
    return [
        'user-edit',
        'user-new',
        'user-edit-network',
        'user-new-network',
        'profile',
        'profile-network',
    ];
}

/**
 * Block disallowed email domains during programmatic user insert/update calls.
 *
 * This is the broader enforcement layer. It catches many plugin-driven flows
 * that bypass the standard registration form and call wp_insert_user() directly.
 *
 * Previously this short-circuited on a blanket is_admin() check, which let any
 * admin-context request (admin-ajax, importers, custom admin pages, REST in
 * admin context) create users with unauthorized domains. We now only short-
 * circuit on the specific user-edit/user-new screens where user_profile_update_errors
 * is guaranteed to render the inline error.
 */
add_filter(
    'wp_pre_insert_user_data',
    function ($data, $update, $user_id, $userdata) {
        if (empty($data['user_email']) || aed_is_email_allowed($data['user_email'])) {
            return $data;
        }

        $screen = function_exists('get_current_screen') ? get_current_screen() : null;
        if ($screen && in_array($screen->id, aed_inline_error_admin_screens(), true)) {
            // user_profile_update_errors will render an inline error here.
            return $data;
        }

        wp_die(
            esc_html__('This email domain is not approved for user accounts on this site.', 'page-authority-allowed-domains'),
            esc_html__('Email Domain Restricted', 'page-authority-allowed-domains'),
            ['response' => 403]
        );
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
                        __('Only approved domains can be used for user accounts. Manage the allowlist under <a href="%s">Users → Allowed Domains</a>.', 'page-authority-allowed-domains'),
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

/**
 * Determine the required capability for managing the allowlist.
 *
 * Single site: manage_options
 * Multisite: manage_network_options
 *
 * @return string
 */
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
            __('Allowed Domains', 'page-authority-allowed-domains'),
            __('Allowed Domains', 'page-authority-allowed-domains'),
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
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Action dispatch only; nonce is verified immediately below.
        $action = isset($_POST['aed_action']) ? sanitize_key(wp_unslash($_POST['aed_action'])) : '';
        if ($action !== 'save_domains') {
            return;
        }

        check_admin_referer('aed_save_domains');

        if (!current_user_can(aed_manage_capability())) {
            wp_die(esc_html__('You do not have permission to manage allowed email domains.', 'page-authority-allowed-domains'));
        }

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
                __('This email domain is not approved for user accounts on this site.', 'page-authority-allowed-domains'),
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
                __('This email domain is not approved for user accounts on this site. Please use an approved email address or contact the site administrator.', 'page-authority-allowed-domains')
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
                __('Your account email domain is not currently approved for this site. Please contact the site administrator.', 'page-authority-allowed-domains')
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
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Action dispatch only; nonce is verified immediately below.
    $action = isset($_POST['aed_action']) ? sanitize_key(wp_unslash($_POST['aed_action'])) : '';
    if ($action !== 'save_login_blocking') {
        return;
    }

    check_admin_referer('aed_save_login_blocking');

    if (!current_user_can(aed_manage_capability())) {
        wp_die(esc_html__('You do not have permission to manage login enforcement.', 'page-authority-allowed-domains'));
    }

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
 * Paginated to avoid loading all users into memory at once on large sites.
 *
 * @return array<int,array<string,string>>
 */
function aed_build_unauthorized_existing_users_audit() {
    if (aed_allowlist_is_empty()) {
        return [];
    }

    $flagged = [];
    $paged   = 1;

    do {
        $users = get_users(
            [
                'fields' => ['ID', 'user_login', 'user_email', 'display_name'],
                'number' => AED_USER_QUERY_BATCH_SIZE,
                'paged'  => $paged,
            ]
        );

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

        $batch_count = count($users);
        $paged++;
    } while ($batch_count === AED_USER_QUERY_BATCH_SIZE);

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
 * Count the content owned by a user that would be affected by deletion.
 *
 * Counts every post of every type owned by the user except auto-drafts and
 * trash entries, which are not user-facing content. This matches the set of
 * posts that wp_delete_user() will either reassign or delete.
 *
 * @param int $user_id User ID.
 * @return int Number of posts owned by the user.
 */
function aed_count_user_owned_content($user_id) {
    $user_id = (int) $user_id;
    if ($user_id <= 0) {
        return 0;
    }

    $cache_key = 'aed_user_content_count_' . $user_id;
    $cached    = wp_cache_get($cache_key, 'aed');

    if (false !== $cached) {
        return (int) $cached;
    }

    global $wpdb;

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- COUNT() is faster than loading all posts; result is cached via wp_cache_set immediately below.
    $count = (int) $wpdb->get_var(
        $wpdb->prepare(
            "SELECT COUNT(ID) FROM {$wpdb->posts} WHERE post_author = %d AND post_status NOT IN ('auto-draft', 'trash')",
            $user_id
        )
    );

    wp_cache_set($cache_key, $count, 'aed', MINUTE_IN_SECONDS);

    return $count;
}

/**
 * Return users whose email domain IS on the allowlist.
 *
 * Used to populate the reassignment dropdown when deleting an unauthorized user.
 * Excludes the user being deleted. Capped at AED_REASSIGN_DROPDOWN_LIMIT to keep
 * the dropdown usable.
 *
 * @param int $exclude_user_id User ID to exclude from the result.
 * @return array{users: array<int,array<string,mixed>>, truncated: bool}
 */
function aed_get_compliant_users_for_reassignment($exclude_user_id) {
    $exclude_user_id = (int) $exclude_user_id;
    $eligible        = [];
    $paged           = 1;
    $truncated       = false;

    do {
        $users = get_users(
            [
                'fields'  => ['ID', 'user_login', 'user_email', 'display_name'],
                'number'  => AED_USER_QUERY_BATCH_SIZE,
                'paged'   => $paged,
                'exclude' => $exclude_user_id > 0 ? [$exclude_user_id] : [],
            ]
        );

        foreach ($users as $user) {
            if (!aed_is_email_allowed($user->user_email)) {
                continue;
            }

            $eligible[] = [
                'id'           => (int) $user->ID,
                'user_login'   => (string) $user->user_login,
                'display_name' => (string) $user->display_name,
                'user_email'   => (string) $user->user_email,
            ];

            if (count($eligible) >= AED_REASSIGN_DROPDOWN_LIMIT) {
                $truncated = true;
                break 2;
            }
        }

        $batch_count = count($users);
        $paged++;
    } while ($batch_count === AED_USER_QUERY_BATCH_SIZE);

    return [
        'users'     => $eligible,
        'truncated' => $truncated,
    ];
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
            <strong><?php esc_html_e('Allowed Email Domains audit warning:', 'page-authority-allowed-domains'); ?></strong>
            <?php
            printf(
                esc_html(
                    /* translators: %d: Number of existing users with unauthorized email domains. */
                    _n(
                        '%d existing user has an email domain that is not currently allowed.',
                        '%d existing users have email domains that are not currently allowed.',
                        count($flagged),
                        'page-authority-allowed-domains'
                    )
                ),
                count($flagged)
            );
            ?>
            <a href="<?php echo esc_url($report_url); ?>">
                <?php esc_html_e('Review the audit report.', 'page-authority-allowed-domains'); ?>
            </a>
        </p>
    </div>
    <?php
}
add_action('admin_notices', 'aed_show_unauthorized_users_admin_notice');



/**
 * AJAX endpoint: return delete-confirmation info for a user.
 *
 * Used by the deletion modal to display the user's owned-content count and the
 * list of compliant users available for reassignment. Read-only — performs no
 * destructive action.
 *
 * Protection:
 * - capability check
 * - per-user nonce
 * - current-user exclusion
 * - multisite Super Admin exclusion
 * - rechecks that the target user is still unauthorized
 *
 * @return void
 */
function aed_ajax_get_user_delete_info() {
    $user_id = isset($_REQUEST['user_id']) ? absint($_REQUEST['user_id']) : 0;

    check_ajax_referer('aed_get_user_delete_info_' . $user_id, 'nonce');

    if (!current_user_can(aed_manage_capability())) {
        wp_send_json_error(
            ['message' => __('You do not have permission to manage users.', 'page-authority-allowed-domains')],
            403
        );
    }

    if ($user_id <= 0) {
        wp_send_json_error(
            ['message' => __('Invalid user.', 'page-authority-allowed-domains')],
            400
        );
    }

    if ($user_id === get_current_user_id()) {
        wp_send_json_error(
            ['message' => __('You cannot delete your own account from the audit.', 'page-authority-allowed-domains')],
            403
        );
    }

    if (is_multisite() && is_super_admin($user_id)) {
        wp_send_json_error(
            ['message' => __('Super Admins cannot be deleted from the audit.', 'page-authority-allowed-domains')],
            403
        );
    }

    $user = get_userdata($user_id);

    if (!$user) {
        wp_send_json_error(
            ['message' => __('User not found.', 'page-authority-allowed-domains')],
            404
        );
    }

    if (aed_is_email_allowed($user->user_email)) {
        wp_send_json_error(
            ['message' => __('This user has an allowed email domain and cannot be deleted from the audit.', 'page-authority-allowed-domains')],
            409
        );
    }

    $content_count = aed_count_user_owned_content($user_id);
    $eligible      = aed_get_compliant_users_for_reassignment($user_id);

    wp_send_json_success(
        [
            'user_id'        => $user_id,
            'user_login'     => $user->user_login,
            'display_name'   => $user->display_name,
            'user_email'     => $user->user_email,
            'content_count'  => $content_count,
            'eligible_users' => $eligible['users'],
            'truncated'      => $eligible['truncated'],
        ]
    );
}
add_action('wp_ajax_aed_get_user_delete_info', 'aed_ajax_get_user_delete_info');


/**
 * Delete one unauthorized user from the Existing User Audit.
 *
 * This action is protected by:
 * - nonce verification (bound to specific user ID)
 * - capability check
 * - current-user exclusion
 * - multisite Super Admin exclusion
 * - revalidation that the selected user is still unauthorized
 * - validation of reassignment target (must exist and have a compliant email)
 * - explicit confirmation when the user owns content (no silent content deletion)
 *
 * Query parameters honored:
 * - reassign_to=N    : reassign content to user N (must be compliant)
 * - aed_delete_content=1 : explicitly delete the user's content (no reassign)
 *
 * If the user owns content and neither parameter is provided, the request is
 * refused. The modal supplies one of these; the failsafe protects admins who
 * have JavaScript disabled.
 *
 * @return void
 */
function aed_handle_delete_unauthorized_user() {
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Action dispatch only; nonce is verified once we know it's our request.
    $action = isset($_GET['aed_action']) ? sanitize_key(wp_unslash($_GET['aed_action'])) : '';
    if ($action !== 'delete_unauthorized_user') {
        return;
    }

    $user_id = isset($_GET['user_id']) ? absint($_GET['user_id']) : 0;

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

    if (!current_user_can(aed_manage_capability())) {
        wp_die(esc_html__('You do not have permission to delete users.', 'page-authority-allowed-domains'));
    }

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

    // Resolve reassignment intent.
    $reassign_to             = isset($_GET['reassign_to']) ? absint($_GET['reassign_to']) : 0;
    $delete_content_confirmed = !empty($_GET['aed_delete_content']);
    $content_count            = aed_count_user_owned_content($user_id);

    if ($content_count > 0 && $reassign_to === 0 && !$delete_content_confirmed) {
        // Failsafe: the modal always sends one of the two parameters. If neither
        // is present and the user owns content, refuse to silently delete it.
        wp_safe_redirect(
            add_query_arg(
                [
                    'page' => 'aed-settings',
                    'aed_delete_error' => 'content_no_confirmation',
                ],
                admin_url('users.php')
            )
        );
        exit;
    }

    if ($reassign_to > 0) {
        if ($reassign_to === $user_id) {
            wp_safe_redirect(
                add_query_arg(
                    [
                        'page' => 'aed-settings',
                        'aed_delete_error' => 'invalid_reassign',
                    ],
                    admin_url('users.php')
                )
            );
            exit;
        }

        $reassign_user = get_userdata($reassign_to);
        if (!$reassign_user) {
            wp_safe_redirect(
                add_query_arg(
                    [
                        'page' => 'aed-settings',
                        'aed_delete_error' => 'invalid_reassign',
                    ],
                    admin_url('users.php')
                )
            );
            exit;
        }

        if (!aed_is_email_allowed($reassign_user->user_email)) {
            wp_safe_redirect(
                add_query_arg(
                    [
                        'page' => 'aed-settings',
                        'aed_delete_error' => 'reassign_not_compliant',
                    ],
                    admin_url('users.php')
                )
            );
            exit;
        }
    }

    if (!function_exists('wp_delete_user')) {
        require_once ABSPATH . 'wp-admin/includes/user.php';
    }

    $deleted = $reassign_to > 0
        ? wp_delete_user($user_id, $reassign_to)
        : wp_delete_user($user_id);

    if ($deleted) {
        aed_clear_audit_cache();
    }

    wp_safe_redirect(
        add_query_arg(
            [
                'page'                 => 'aed-settings',
                'aed_deleted_user'     => $deleted ? 1 : 0,
                'aed_deleted_id'       => $user_id,
                'aed_deleted_reassign' => $reassign_to,
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
 * - nonce verification (bound to the requested domain, verified first)
 * - capability check
 * - domain normalization/validation
 *
 * The nonce is verified against the raw URL "domain" value before normalization
 * so an attacker cannot mutate the URL to a different domain and reuse a nonce
 * that was generated for some other domain.
 *
 * After saving, the admin is redirected back to the audit section so the list
 * refreshes immediately with the updated allowlist.
 *
 * @return void
 */
function aed_handle_add_audit_domain_to_allowlist() {
    $raw_domain = isset($_GET['domain']) ? sanitize_text_field(wp_unslash($_GET['domain'])) : '';

    // Verify the nonce first. It is keyed to the raw URL domain value, so a
    // tampered URL fails here before anything else runs.
    check_admin_referer('aed_add_audit_domain_' . md5($raw_domain));

    if (!current_user_can(aed_manage_capability())) {
        wp_die(esc_html__('You do not have permission to manage allowed domains.', 'page-authority-allowed-domains'));
    }

    $domain = aed_normalize_domain($raw_domain);

    if (!$domain) {
        wp_safe_redirect(aed_get_settings_url(['aed_add_error' => 'invalid_domain'], 'aed-existing-user-audit'));
        exit;
    }

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
 * Map a delete-error code to a human-readable notice.
 *
 * @param string $code Error code from the redirect URL.
 * @return string Localized message, or empty string when the code is unknown.
 */
function aed_delete_error_message($code) {
    switch ($code) {
        case 'missing_user':
            return __('No user was specified for deletion.', 'page-authority-allowed-domains');
        case 'current_user':
            return __('You cannot delete your own account from the audit.', 'page-authority-allowed-domains');
        case 'super_admin':
            return __('Super Admins cannot be deleted from the audit.', 'page-authority-allowed-domains');
        case 'not_found':
            return __('That user no longer exists.', 'page-authority-allowed-domains');
        case 'user_allowed':
            return __('That user now has an allowed email domain. Deletion was cancelled.', 'page-authority-allowed-domains');
        case 'content_no_confirmation':
            return __('The selected user owns posts or pages. Please confirm whether to reassign or delete that content before deleting the user.', 'page-authority-allowed-domains');
        case 'invalid_reassign':
            return __('The user selected for reassignment is invalid.', 'page-authority-allowed-domains');
        case 'reassign_not_compliant':
            return __('Content can only be reassigned to a user with an approved email domain.', 'page-authority-allowed-domains');
        default:
            return '';
    }
}

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

    // phpcs:disable WordPress.Security.NonceVerification.Recommended -- Display-only notice flags set by this plugin's own redirects after nonce-verified actions; the page itself is capability-checked above and performs no state changes.
    $aed_updated_notice                = isset($_GET['updated']) ? sanitize_text_field(wp_unslash($_GET['updated'])) : '';
    $aed_added_domain_notice           = isset($_GET['aed_added_domain']) ? sanitize_text_field(wp_unslash($_GET['aed_added_domain'])) : '';
    $aed_add_error_notice              = isset($_GET['aed_add_error']) ? sanitize_text_field(wp_unslash($_GET['aed_add_error'])) : '';
    $aed_login_blocking_updated_notice = isset($_GET['aed_login_blocking_updated']) ? sanitize_text_field(wp_unslash($_GET['aed_login_blocking_updated'])) : '';
    $aed_deleted_user_notice           = isset($_GET['aed_deleted_user']) ? absint($_GET['aed_deleted_user']) : 0;
    $aed_deleted_reassign_notice       = isset($_GET['aed_deleted_reassign']) ? absint($_GET['aed_deleted_reassign']) : 0;
    $aed_delete_error_notice           = isset($_GET['aed_delete_error']) ? sanitize_text_field(wp_unslash($_GET['aed_delete_error'])) : '';
    $aed_deleted_id_present            = !empty($_GET['aed_deleted_id']);
    // phpcs:enable WordPress.Security.NonceVerification.Recommended

    ?>
    <div class="wrap">
        <h1><?php esc_html_e('Allowed Email Domains', 'page-authority-allowed-domains'); ?></h1>

        <?php if (!empty($aed_updated_notice)) : ?>
            <div class="notice notice-success is-dismissible">
                <p><?php esc_html_e('Allowed email domains updated.', 'page-authority-allowed-domains'); ?></p>
            </div>
        <?php endif; ?>

        <?php if (!empty($aed_login_blocking_updated_notice)) : ?>
            <div class="notice notice-success is-dismissible">
                <p><?php esc_html_e('Login enforcement setting saved.', 'page-authority-allowed-domains'); ?></p>
            </div>
        <?php endif; ?>

        <?php if (!empty($aed_added_domain_notice)) : ?>
            <div class="notice notice-success is-dismissible">
                <p>
                    <?php esc_html_e('Domain added to the allowlist:', 'page-authority-allowed-domains'); ?>
                    <code><?php echo esc_html($aed_added_domain_notice); ?></code>
                </p>
            </div>
        <?php endif; ?>

        <?php if ($aed_add_error_notice === 'invalid_domain') : ?>
            <div class="notice notice-error is-dismissible">
                <p><?php esc_html_e('The domain could not be added. Make sure it is a valid domain (e.g. @example.com).', 'page-authority-allowed-domains'); ?></p>
            </div>
        <?php endif; ?>

        <?php if ($aed_deleted_user_notice === 1) : ?>
            <div class="notice notice-success is-dismissible">
                <p>
                    <?php
                    if ($aed_deleted_reassign_notice > 0) {
                        $reassign_user = get_userdata($aed_deleted_reassign_notice);
                        $reassign_label = $reassign_user
                            ? ($reassign_user->display_name ?: $reassign_user->user_login)
                            : sprintf(
                                /* translators: %d: User ID. */
                                __('user #%d', 'page-authority-allowed-domains'),
                                $aed_deleted_reassign_notice
                            );
                        printf(
                            /* translators: %s: display name of the user content was reassigned to. */
                            esc_html__('User deleted. Their content was reassigned to %s.', 'page-authority-allowed-domains'),
                            '<strong>' . esc_html($reassign_label) . '</strong>'
                        );
                    } else {
                        esc_html_e('User deleted.', 'page-authority-allowed-domains');
                    }
                    ?>
                </p>
            </div>
        <?php elseif ($aed_deleted_user_notice === 0 && $aed_deleted_id_present) : ?>
            <div class="notice notice-error is-dismissible">
                <p><?php esc_html_e('User could not be deleted. Please try again.', 'page-authority-allowed-domains'); ?></p>
            </div>
        <?php endif; ?>

        <?php
        $delete_error_message = aed_delete_error_message($aed_delete_error_notice);
        if ($delete_error_message !== '') :
            ?>
            <div class="notice notice-error is-dismissible">
                <p><?php echo esc_html($delete_error_message); ?></p>
            </div>
        <?php endif; ?>

        <?php if (aed_allowlist_is_empty()) : ?>
            <div class="notice notice-warning">
                <p>
                    <?php esc_html_e('No domains are configured. All email domains are currently allowed.', 'page-authority-allowed-domains'); ?>
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
                            <?php esc_html_e('Allowed Email Domains', 'page-authority-allowed-domains'); ?>
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
                            <?php esc_html_e('One domain per line. Entries are normalized to start with "@". A valid suffix/TLD is required. Empty list allows all domains.', 'page-authority-allowed-domains'); ?>
                        </p>
                    </td>
                </tr>
            </table>

            <?php submit_button(__('Save Domains', 'page-authority-allowed-domains')); ?>
        </form>


        <hr>

        <h2><?php esc_html_e('Login Enforcement', 'page-authority-allowed-domains'); ?></h2>

        <p>
            <?php esc_html_e('Optional login blocking prevents existing users with unauthorized email domains from signing in. Leave this disabled until you have reviewed the Existing User Audit to avoid accidental lockouts.', 'page-authority-allowed-domains'); ?>
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
                <?php esc_html_e('Block login for users whose email domain is not allowed', 'page-authority-allowed-domains'); ?>
            </label>

            <?php submit_button(__('Save Login Enforcement Setting', 'page-authority-allowed-domains')); ?>
        </form>

        <hr id="aed-existing-user-audit">

        <h2><?php esc_html_e('Existing User Audit', 'page-authority-allowed-domains'); ?></h2>

        <p>
            <?php esc_html_e('This report flags existing users whose email domains are not currently on the allowed list. It is audit-only and does not disable, delete, or modify users.', 'page-authority-allowed-domains'); ?>
        </p>

        <?php $unauthorized_users = aed_get_unauthorized_existing_users(); ?>

        <?php if (aed_allowlist_is_empty()) : ?>
            <div class="notice notice-info inline">
                <p><?php esc_html_e('No audit results are shown because the allowlist is empty and all domains are currently allowed.', 'page-authority-allowed-domains'); ?></p>
            </div>
        <?php elseif (empty($unauthorized_users)) : ?>
            <div class="notice notice-success inline">
                <p><?php esc_html_e('No existing users with unauthorized email domains were found.', 'page-authority-allowed-domains'); ?></p>
            </div>
        <?php else : ?>
            <div class="notice notice-warning inline">
                <p>
                    <strong><?php esc_html_e('Action recommended:', 'page-authority-allowed-domains'); ?></strong>
                    <?php esc_html_e('Review these users, update their email addresses, add the appropriate domains to the allowlist, or delete individual unauthorized users.', 'page-authority-allowed-domains'); ?>
                </p>
            </div>

            <table class="widefat striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e('User', 'page-authority-allowed-domains'); ?></th>
                        <th><?php esc_html_e('Username', 'page-authority-allowed-domains'); ?></th>
                        <th><?php esc_html_e('Email', 'page-authority-allowed-domains'); ?></th>
                        <th><?php esc_html_e('Domain', 'page-authority-allowed-domains'); ?></th>
                        <th><?php esc_html_e('Action', 'page-authority-allowed-domains'); ?></th>
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
                                    <?php esc_html_e('Edit user', 'page-authority-allowed-domains'); ?>
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
                                    <?php esc_html_e('Add domain', 'page-authority-allowed-domains'); ?>
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
                                $info_nonce = wp_create_nonce('aed_get_user_delete_info_' . (int) $audit_user['id']);
                                ?>
                                <a
                                    href="<?php echo esc_url($delete_url); ?>"
                                    class="submitdelete aed-delete-user-link"
                                    data-aed-user-id="<?php echo esc_attr((int) $audit_user['id']); ?>"
                                    data-aed-info-nonce="<?php echo esc_attr($info_nonce); ?>"
                                    data-aed-user-label="<?php echo esc_attr($audit_user['display_name'] ?: $audit_user['user_login']); ?>"
                                >
                                    <?php esc_html_e('Delete user', 'page-authority-allowed-domains'); ?>
                                </a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <?php aed_render_delete_user_modal(); ?>
        <?php endif; ?>


        <hr>

        <h2><?php esc_html_e('Recent Allowlist Changes', 'page-authority-allowed-domains'); ?></h2>

        <table class="widefat striped">
            <thead>
                <tr>
                    <th><?php esc_html_e('Timestamp', 'page-authority-allowed-domains'); ?></th>
                    <th><?php esc_html_e('Admin', 'page-authority-allowed-domains'); ?></th>
                    <th><?php esc_html_e('Domains', 'page-authority-allowed-domains'); ?></th>
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
                        <td colspan="3"><?php esc_html_e('No changes logged yet.', 'page-authority-allowed-domains'); ?></td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
    <?php
}


/**
 * Render the delete-user confirmation modal (markup, styles, behavior).
 *
 * The modal is hidden by default and only shown when an admin clicks a
 * "Delete user" link in the audit table. It fetches per-user info over AJAX
 * (post/page count + list of compliant users) and gives the admin three
 * explicit choices when content is present:
 *   1. Reassign all content to a compliant user (dropdown)
 *   2. Delete the user and all their content
 *   3. Cancel
 *
 * When the user owns no content, only "Delete user" and "Cancel" are shown.
 *
 * @return void
 */
function aed_render_delete_user_modal() {
    ?>
    <div id="aed-delete-modal" class="aed-modal" hidden role="dialog" aria-modal="true" aria-labelledby="aed-modal-title">
        <div class="aed-modal-backdrop" data-aed-close></div>
        <div class="aed-modal-dialog" role="document">
            <header class="aed-modal-header">
                <h2 id="aed-modal-title"><?php esc_html_e('Delete unauthorized user', 'page-authority-allowed-domains'); ?></h2>
                <button type="button" class="aed-modal-close" aria-label="<?php esc_attr_e('Close', 'page-authority-allowed-domains'); ?>" data-aed-close>&times;</button>
            </header>

            <div class="aed-modal-body">
                <div class="aed-modal-loading">
                    <p><?php esc_html_e('Loading user details…', 'page-authority-allowed-domains'); ?></p>
                </div>

                <div class="aed-modal-error notice notice-error inline" hidden>
                    <p data-aed-error-message></p>
                </div>

                <div class="aed-modal-content" hidden>
                    <p>
                        <?php
                        printf(
                            /* translators: %s: user display name. */
                            esc_html__('You are about to delete %s.', 'page-authority-allowed-domains'),
                            '<strong data-aed-user-label></strong>'
                        );
                        ?>
                        <br>
                        <span class="description" data-aed-user-email></span>
                    </p>

                    <div class="aed-modal-content-none" hidden>
                        <p><?php esc_html_e('This user does not own any posts or pages. Their account will be removed.', 'page-authority-allowed-domains'); ?></p>
                    </div>

                    <div class="aed-modal-content-present" hidden>
                        <p>
                            <strong data-aed-content-count></strong>
                            <?php esc_html_e('What should happen to their content?', 'page-authority-allowed-domains'); ?>
                        </p>

                        <fieldset class="aed-reassign-options">
                            <label class="aed-reassign-option">
                                <input type="radio" name="aed-reassign-mode" value="reassign" checked>
                                <span><?php esc_html_e('Reassign all content to:', 'page-authority-allowed-domains'); ?></span>
                            </label>

                            <select class="aed-reassign-select" aria-label="<?php esc_attr_e('Reassign content to user', 'page-authority-allowed-domains'); ?>">
                                <option value=""><?php esc_html_e('— Select a user —', 'page-authority-allowed-domains'); ?></option>
                            </select>

                            <p class="aed-reassign-truncated description" hidden>
                                <?php
                                printf(
                                    /* translators: %d: maximum number of users shown. */
                                    esc_html__('Showing the first %d compliant users. Use the WordPress Users screen for sites with larger lists.', 'page-authority-allowed-domains'),
                                    (int) AED_REASSIGN_DROPDOWN_LIMIT
                                );
                                ?>
                            </p>

                            <p class="aed-reassign-empty description" hidden>
                                <?php esc_html_e('No other users with an approved email domain exist yet. Add a compliant user before reassigning content, or choose "Delete all content" below.', 'page-authority-allowed-domains'); ?>
                            </p>

                            <label class="aed-reassign-option">
                                <input type="radio" name="aed-reassign-mode" value="delete">
                                <span><?php esc_html_e('Delete the user and all their content', 'page-authority-allowed-domains'); ?></span>
                            </label>

                            <p class="description aed-delete-content-warning">
                                <?php esc_html_e('Deleting content is permanent. Make sure you have a recent backup.', 'page-authority-allowed-domains'); ?>
                            </p>
                        </fieldset>
                    </div>
                </div>
            </div>

            <footer class="aed-modal-footer" hidden>
                <button type="button" class="button" data-aed-close><?php esc_html_e('Cancel', 'page-authority-allowed-domains'); ?></button>
                <button type="button" class="button button-primary aed-modal-confirm" disabled>
                    <?php esc_html_e('Confirm deletion', 'page-authority-allowed-domains'); ?>
                </button>
            </footer>
        </div>
    </div>

    <style>
        .aed-modal[hidden] { display: none; }
        .aed-modal {
            position: fixed; inset: 0; z-index: 160000;
            display: flex; align-items: center; justify-content: center;
        }
        .aed-modal-backdrop {
            position: absolute; inset: 0;
            background: rgba(0, 0, 0, 0.55);
        }
        .aed-modal-dialog {
            position: relative;
            background: #fff;
            border-radius: 4px;
            box-shadow: 0 6px 32px rgba(0, 0, 0, 0.28);
            width: 560px; max-width: calc(100vw - 32px);
            max-height: calc(100vh - 64px);
            display: flex; flex-direction: column;
        }
        .aed-modal-header {
            display: flex; align-items: center; justify-content: space-between;
            padding: 14px 18px;
            border-bottom: 1px solid #dcdcde;
        }
        .aed-modal-header h2 { margin: 0; font-size: 16px; line-height: 1.4; }
        .aed-modal-close {
            background: transparent; border: 0; cursor: pointer;
            font-size: 24px; line-height: 1; color: #50575e;
            padding: 0 4px;
        }
        .aed-modal-close:hover { color: #135e96; }
        .aed-modal-body {
            padding: 18px;
            overflow-y: auto;
            flex: 1 1 auto;
        }
        .aed-modal-footer {
            display: flex; justify-content: flex-end; gap: 8px;
            padding: 12px 18px;
            border-top: 1px solid #dcdcde;
            background: #f6f7f7;
            border-bottom-left-radius: 4px;
            border-bottom-right-radius: 4px;
        }
        .aed-modal-loading p { margin: 0; color: #50575e; }
        .aed-modal-error { margin: 0 0 12px; }
        .aed-reassign-options { border: 0; margin: 0; padding: 0; }
        .aed-reassign-option { display: block; margin: 8px 0 4px; }
        .aed-reassign-option input { margin-right: 6px; }
        .aed-reassign-select { display: block; margin: 6px 0 12px 24px; min-width: 280px; max-width: 100%; }
        .aed-reassign-truncated,
        .aed-reassign-empty { margin: 0 0 12px 24px; }
        .aed-delete-content-warning { color: #8a2424; margin-left: 24px; }
    </style>

    <script>
    (function () {
        document.addEventListener('DOMContentLoaded', function () {
            var modal = document.getElementById('aed-delete-modal');
            if (!modal) { return; }

            var links = document.querySelectorAll('.aed-delete-user-link');
            if (!links.length) { return; }

            var loadingEl    = modal.querySelector('.aed-modal-loading');
            var errorEl      = modal.querySelector('.aed-modal-error');
            var errorMsgEl   = modal.querySelector('[data-aed-error-message]');
            var contentEl    = modal.querySelector('.aed-modal-content');
            var footerEl     = modal.querySelector('.aed-modal-footer');
            var confirmBtn   = modal.querySelector('.aed-modal-confirm');
            var labelEl      = modal.querySelector('[data-aed-user-label]');
            var emailEl      = modal.querySelector('[data-aed-user-email]');
            var noneSection  = modal.querySelector('.aed-modal-content-none');
            var presSection  = modal.querySelector('.aed-modal-content-present');
            var countEl      = modal.querySelector('[data-aed-content-count]');
            var selectEl     = modal.querySelector('.aed-reassign-select');
            var truncatedEl  = modal.querySelector('.aed-reassign-truncated');
            var emptyEl      = modal.querySelector('.aed-reassign-empty');
            var modeInputs   = modal.querySelectorAll('input[name="aed-reassign-mode"]');

            var currentHref       = '';
            var currentContentNum = 0;

            function resetModal() {
                loadingEl.hidden  = false;
                errorEl.hidden    = true;
                contentEl.hidden  = true;
                footerEl.hidden   = true;
                noneSection.hidden = true;
                presSection.hidden = true;
                truncatedEl.hidden = true;
                emptyEl.hidden     = true;
                selectEl.innerHTML = '<option value=""><?php echo esc_js(__('— Select a user —', 'page-authority-allowed-domains')); ?></option>';
                confirmBtn.disabled = true;
                modeInputs.forEach(function (input) {
                    input.checked = (input.value === 'reassign');
                    input.disabled = false;
                });
            }

            function openModal() {
                resetModal();
                modal.hidden = false;
                document.body.style.overflow = 'hidden';
            }

            function closeModal() {
                modal.hidden = true;
                document.body.style.overflow = '';
                currentHref = '';
                currentContentNum = 0;
            }

            function showError(message) {
                loadingEl.hidden = true;
                errorEl.hidden   = false;
                contentEl.hidden = true;
                footerEl.hidden  = false;
                confirmBtn.hidden = true;
                errorMsgEl.textContent = message || '<?php echo esc_js(__('Unexpected error.', 'page-authority-allowed-domains')); ?>';
            }

            function populate(data) {
                loadingEl.hidden = true;
                errorEl.hidden   = true;
                contentEl.hidden = false;
                footerEl.hidden  = false;
                confirmBtn.hidden = false;

                labelEl.textContent = data.display_name || data.user_login || '';
                emailEl.textContent = data.user_email || '';

                currentContentNum = parseInt(data.content_count, 10) || 0;

                if (currentContentNum === 0) {
                    noneSection.hidden = false;
                    presSection.hidden = true;
                    confirmBtn.disabled = false;
                    return;
                }

                noneSection.hidden = true;
                presSection.hidden = false;

                // Build a localized "owns N posts/pages" message.
                var phrase = (currentContentNum === 1)
                    ? '<?php echo esc_js(__('This user owns 1 post or page.', 'page-authority-allowed-domains')); ?>'
                    : '<?php echo esc_js(__('This user owns COUNT posts or pages.', 'page-authority-allowed-domains')); ?>'.replace('COUNT', currentContentNum);
                countEl.textContent = phrase;

                var eligible = Array.isArray(data.eligible_users) ? data.eligible_users : [];
                if (eligible.length === 0) {
                    emptyEl.hidden = false;
                    // Force "delete" mode and disable reassign radio.
                    modeInputs.forEach(function (input) {
                        if (input.value === 'reassign') {
                            input.disabled = true;
                            input.checked  = false;
                        }
                        if (input.value === 'delete') {
                            input.checked = true;
                        }
                    });
                    selectEl.disabled = true;
                } else {
                    eligible.forEach(function (user) {
                        var opt = document.createElement('option');
                        opt.value = String(user.id);
                        var label = user.display_name || user.user_login || ('User #' + user.id);
                        opt.textContent = label + ' (' + (user.user_email || '') + ')';
                        selectEl.appendChild(opt);
                    });
                    if (data.truncated) {
                        truncatedEl.hidden = false;
                    }
                }

                updateConfirmState();
            }

            function selectedMode() {
                var sel = modal.querySelector('input[name="aed-reassign-mode"]:checked');
                return sel ? sel.value : '';
            }

            function updateConfirmState() {
                if (currentContentNum === 0) {
                    confirmBtn.disabled = false;
                    return;
                }
                var mode = selectedMode();
                if (mode === 'reassign') {
                    confirmBtn.disabled = !selectEl.value;
                } else if (mode === 'delete') {
                    confirmBtn.disabled = false;
                } else {
                    confirmBtn.disabled = true;
                }
            }

            function buildFinalUrl() {
                if (!currentHref) { return ''; }
                var url;
                try {
                    url = new URL(currentHref, window.location.origin);
                } catch (e) {
                    return currentHref;
                }

                if (currentContentNum === 0) {
                    // No content — no extra params required, but mark explicit
                    // so the server's failsafe sees a deliberate request.
                    url.searchParams.set('aed_delete_content', '1');
                    return url.toString();
                }

                var mode = selectedMode();
                if (mode === 'reassign' && selectEl.value) {
                    url.searchParams.set('reassign_to', selectEl.value);
                } else {
                    url.searchParams.set('aed_delete_content', '1');
                }
                return url.toString();
            }

            function fetchInfo(userId, infoNonce) {
                var body = new URLSearchParams();
                body.append('action', 'aed_get_user_delete_info');
                body.append('user_id', userId);
                body.append('nonce', infoNonce);

                fetch(window.ajaxurl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
                    body: body.toString()
                })
                .then(function (response) {
                    return response.json().catch(function () {
                        throw new Error('<?php echo esc_js(__('Server returned an unexpected response.', 'page-authority-allowed-domains')); ?>');
                    });
                })
                .then(function (json) {
                    if (!json || !json.success) {
                        var msg = (json && json.data && json.data.message)
                            ? json.data.message
                            : '<?php echo esc_js(__('Unable to load user details.', 'page-authority-allowed-domains')); ?>';
                        showError(msg);
                        return;
                    }
                    populate(json.data || {});
                })
                .catch(function (err) {
                    showError(err && err.message ? err.message : '<?php echo esc_js(__('Network error.', 'page-authority-allowed-domains')); ?>');
                });
            }

            // Wire link clicks.
            links.forEach(function (link) {
                link.addEventListener('click', function (event) {
                    var userId    = this.getAttribute('data-aed-user-id');
                    var infoNonce = this.getAttribute('data-aed-info-nonce');
                    if (!userId || !infoNonce) { return; }

                    event.preventDefault();
                    currentHref = this.getAttribute('href');
                    openModal();
                    fetchInfo(userId, infoNonce);
                });
            });

            // Wire modal interactions.
            modal.addEventListener('click', function (event) {
                if (event.target.matches('[data-aed-close]')) {
                    closeModal();
                }
            });

            document.addEventListener('keydown', function (event) {
                if (event.key === 'Escape' && !modal.hidden) {
                    closeModal();
                }
            });

            modeInputs.forEach(function (input) {
                input.addEventListener('change', updateConfirmState);
            });

            selectEl.addEventListener('change', updateConfirmState);

            confirmBtn.addEventListener('click', function () {
                var url = buildFinalUrl();
                if (url) {
                    confirmBtn.disabled = true;
                    confirmBtn.textContent = '<?php echo esc_js(__('Deleting…', 'page-authority-allowed-domains')); ?>';
                    window.location.href = url;
                }
            });
        });
    })();
    </script>
    <?php
}



/**
 * Add quick plugin action links on the Plugins screen.
 *
 * Adds:
 * - Settings
 *
 * This improves admin navigation and provides quick access directly from the
 * Plugins page.
 *
 * @param array $links Existing plugin action links.
 * @return array
 */
function aed_plugin_action_links($links) {

    $settings_link =
        '<a href="' .
        esc_url(admin_url('users.php?page=aed-settings')) .
        '">' .
        esc_html__('Settings', 'page-authority-allowed-domains') .
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

    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading the standard WordPress bulk-activation flag to opt out of redirect; no state change here.
    if (isset($_GET['activate-multi'])) {
        return;
    }

    wp_safe_redirect(
        admin_url('users.php?page=aed-settings')
    );

    exit;
}

add_action('admin_init', 'aed_do_activation_redirect');


/**
 * Add GitHub to the plugin row metadata on the Plugins screen.
 *
 * @param array  $links Plugin row meta links.
 * @param string $file  Plugin file path.
 * @return array
 */
function aed_plugin_row_meta_links($links, $file) {

    if ($file !== plugin_basename(__FILE__)) {
        return $links;
    }

    $links[] =
        '<a href="https://github.com/TWestford/Page-Authority-Allowed-Domains" target="_blank" rel="noopener noreferrer">' .
        esc_html__('GitHub', 'page-authority-allowed-domains') .
        '</a>';

    return $links;
}

add_filter('plugin_row_meta', 'aed_plugin_row_meta_links', 10, 2);
