=== Page Authority - Allowed Domains ===
Contributors: twestford
Tags: users, security, registration, email, domains
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 1.8.15
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
* Per-user unauthorized account removal
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

Deletion actions are protected by capability checks, nonce verification, confirmation prompts, current-admin protection, and multisite Super Admin protection.

= Can users with unauthorized domains be blocked from logging in? =

Yes. Optional login enforcement can be enabled after reviewing the Existing User Audit.

Login enforcement is disabled by default to avoid accidental lockouts.

= Does this plugin create custom database tables? =

No. The plugin stores settings using WordPress options and does not create custom database tables.

== Security Notes ==

The plugin includes:

* Capability checks
* Nonce verification
* Sanitization and escaping
* Live revalidation before destructive actions
* Current-admin protection
* Multisite Super Admin protection

Recommended operational practices:

* Review the Existing User Audit before enabling login blocking
* Test custom registration and SSO flows before production rollout
* Maintain regular database backups before deleting users
* Restrict plugin management access to trusted administrators only

== Uninstall ==

Deleting the plugin removes:

* `aed_allowed_domains`
* `aed_audit_log`
* `aed_block_unauthorized_logins`

On multisite, the matching network options are also removed.

== Changelog ==

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
