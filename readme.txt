=== Page Authority - Allowed Domains ===
Contributors: twestford
Tags: users, security, registration, email, domains
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restrict WordPress user accounts to administrator-approved email domains.

== Description ==

Allowed Email Domains gives administrators a simple way to restrict WordPress user accounts to approved email domains.

The plugin is designed for sites where only users from specific organizations, companies, clients, or teams should be added as WordPress users.

Features include:

* Admin-managed allowed domain list
* Standard WordPress registration enforcement
* REST API user creation/update enforcement
* WooCommerce registration enforcement
* Existing User Audit tools
* Optional login enforcement
* Per-user unauthorized account removal with content reassignment
* Multisite-aware protections
* Lightweight architecture with no custom database tables

== Installation ==

1. Upload the zip file to `wp-content/plugins/`
2. Activate **Allowed Email Domains** in WordPress Admin
3. Go to **Users > Allowed Domains**
4. Add approved domains, one per line

== Frequently Asked Questions ==

= What format should allowed domains use? =

Enter one domain per line. Domains are normalized to begin with `@`.

Example:

`@example.com`
`@company.org`
`@agency.net`

= What happens if the allowlist is empty? =

If the allowlist is empty, all email domains are allowed.

= Does this affect existing users? =

Existing users are not automatically disabled, deleted, modified, or logged out.

The Existing User Audit identifies existing users whose email domains are not currently allowed. Administrators can review those users individually.

= Can unauthorized users be deleted? =

Yes. The audit table includes per-user delete actions for unauthorized users.

When a user owns posts or pages, a confirmation modal appears with a dropdown of compliant users (those whose email is on the allowlist) for content reassignment. Administrators can also choose to delete the user and all their content.

Deletion actions are protected by nonce verification, capability checks, confirmation prompts, current-admin protection, multisite Super Admin protection, and a server-side failsafe that refuses to silently delete a user's content.

= Can users with unauthorized domains be blocked from logging in? =

Yes. Optional login enforcement can be enabled after reviewing the Existing User Audit.

Login enforcement is disabled by default to avoid accidental lockouts.

= Does this plugin create custom database tables? =

No. The plugin stores settings using WordPress options and does not create custom database tables.

== Security Notes ==

The plugin includes:

* Capability checks
* Nonce verification (verified before any state-changing logic runs)
* Sanitization and escaping
* Live revalidation before destructive actions
* Current-admin protection
* Multisite Super Admin protection
* Explicit content reassignment or delete confirmation before user removal

Recommended operational practices:

* Review the Existing User Audit before enabling login blocking
* Test custom registration and SSO flows before production rollout
* Maintain regular database backups before deleting users
* Restrict plugin management access to trusted administrators only

== Screenshots ==

1. The Allowed Domains settings page where administrators manage the email domain allowlist, with optional login enforcement and an existing user audit.
2. Inline admin error shown when an administrator attempts to add a user with an unauthorized email domain.
3. The Existing User Audit identifies users whose email domains are not currently approved and offers per-user actions.
4. Content reassignment modal appears when deleting an unauthorized user who owns posts or pages.
5. Recent allowlist changes log tracks who modified the allowlist and when.

== Uninstall ==

Deleting the plugin removes its current options:

* `pageauth_allowed_domains`
* `pageauth_audit_log`
* `pageauth_block_unauthorized_logins`

It also cleans up internal flags, transients, user meta, and any leftover keys from prior plugin versions that used the `paad_` or `aed_` prefixes. On multisite, the matching network options are removed as well.

== Changelog ==

= 2.0.0 =
* Compliance: renamed internal prefix from `paad_` (4 characters) to `pageauth_` (8 characters) across functions, constants, options, transients, user meta, nonces, AJAX actions, hooks, page slug, CSS classes, HTML IDs, and JavaScript data attributes. The new prefix is unique, brand-aligned, and far less likely to collide with any other plugin
* Migration: existing allowlist, audit log, and login-blocking preference are migrated transparently on upgrade from either prior prefix (`paad_` from 1.9.1 or `aed_` from 1.9.0 and earlier)
* Compatibility: both legacy settings URLs (`users.php?page=aed-settings` and `users.php?page=paad-settings`) now redirect to the current `pageauth-settings` slug
* Cleanup: `uninstall.php` removes both the current and all legacy option, transient, and user-meta keys, so removal is clean regardless of which version was last installed

= 1.9.1 =
* Compliance: renamed internal prefix from `aed_` (3 characters) to `paad_` (4 characters) across functions, constants, options, transients, nonces, AJAX actions, page slug, CSS classes, and HTML IDs to meet WordPress.org Plugin Directory naming requirements.
* Migration: existing allowlist, audit log, and login-blocking preference are migrated transparently on upgrade.
* Compatibility: legacy `users.php?page=aed-settings` URL now redirects to the new `paad-settings` slug.
* Cleanup: rewrote `uninstall.php` to actually remove the options the plugin stores (the previous file targeted a key prefix that was never written), and added cleanup for legacy `aed_*` keys.

= 1.9.0 =
* Security: nonce verification now runs before capability checks and before any input processing in the audit-domain-add and user-delete handlers
* Security: programmatic user creation in admin context (admin-ajax, importers, REST in admin) is no longer silently allowed; only the user-edit/user-new screens defer to the inline error path
* Performance: existing-user audit query is paginated to avoid loading every user into memory on large sites
* Feature: deleting an unauthorized user who owns posts or pages now opens a confirmation modal with a dropdown of compliant users for content reassignment, or an explicit "delete content" option
* Feature: success notice when a domain is added directly from the audit
* Feature: clearer error notices for delete failures (missing user, current user, super admin, allowed-now, content-without-confirmation, invalid reassignment target)
* Hardening: server-side failsafe refuses to delete a user with owned content unless reassignment or explicit content-delete is specified
* Hardening: reassignment target is revalidated as a real, compliant user before deletion proceeds
* Cleanup: removed dead query-parameter handling, consistent input handling throughout

= 1.8.15 =
* Removed redundant GitHub plugin site link from the Plugins screen.

= 1.8.14 =
* Added GitHub plugin metadata link on the WordPress Plugins screen.
* Added Page Authority author URL metadata.

= 1.8.12 =
* Cleaned and consolidated changelog entries

= 1.8.11 =
* Updated WordPress.org plugin slug and text domain compatibility
* Fixed automated scan compatibility issues

= 1.8.9 =
* Renamed plugin to "Page Authority - Allowed Domains"

= 1.8.2 =
* Added unauthorized user audit tools
* Added quick actions for adding domains and deleting users

= 1.8.1 =
* Added login enforcement protections for unauthorized domains

= 1.8.0 =
* Added WooCommerce, REST API, and multisite enforcement support

= 1.7.0 =
* Added GitHub update compatibility support
* Improved admin navigation and documentation

= 1.6.0 =
* Improved validation, admin UX, and security handling

= 1.5.0 =
* Added uninstall cleanup and compatibility metadata

= 1.0.0 =
* Initial plugin release
