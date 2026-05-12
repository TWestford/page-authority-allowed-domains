=== Page Authority - Allowed Domains ===
Contributors: twestford
Tags: users, security, registration, email, domains
Requires at least: 6.0
Tested up to: 6.9.4
Requires PHP: 7.4
Stable tag: 1.8.9
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

= 1.8.9 =
* Updated plugin display name to "Page Authority - Allowed Domains" for WordPress.org naming compliance.

= 1.8.8 =
* Updated compatibility metadata to reflect testing on WordPress 6.9.4.

= 1.8.7 =
* Packaged under the lowercase WordPress plugin slug allowed-email-domains.
* Normalized text domain to match the lowercase plugin folder.
* Removed hidden files from the distributable ZIP.
* Set Tested up to to a Plugin Check-recognized version.

= 1.8.5 =
* Updated package folder and text domain to lowercase format.
* Matched Tested up to values between plugin header and readme.txt.
* Removed hidden files from the submission package.

= 1.8.4 =
* Updated text domain to match the current package slug used by Plugin Check.
* Adjusted Tested up to value to a valid WordPress.org readme format.
* Removed hidden files from the package.
* Replaced remaining direct activation query check with sanitized input handling.

= 1.8.3 =
* Fixed text domain header and localization domains for WordPress.org checks.
* Added translator comments for placeholder strings.
* Removed update-specific metadata from the WordPress.org package.
* Improved request sanitization for plugin check compatibility.

= 1.8.2 =
* Prepared package for WordPress.org-style distribution
* Removed GitHub updater-specific plugin headers
* Added WordPress.org-compatible readme.txt
* Removed external updater documentation from the packaged README

= 1.8.1 =
* Added automatic redirect to the Allowed Domains settings page after plugin activation
* Skips redirect during bulk activations and unauthorized admin contexts

= 1.8.0 =
* Updated repository URLs

= 1.7.x =
* Added quick audit actions
* Added GitHub metadata links for non-WordPress.org distribution
* Added short-lived audit caching
* Improved admin navigation

= 1.6.x =
* Added Existing User Audit
* Added login enforcement option
* Added REST API and WooCommerce enforcement
* Added unauthorized-user management tools
* Added security documentation and compatibility metadata

= 1.5.x =
* Improved admin validation UX
* Added inline error messaging
* Added uninstall handling
* Improved plugin metadata and documentation

= 1.0.0 =
* Initial release
