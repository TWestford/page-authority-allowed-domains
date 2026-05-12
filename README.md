# Page Authority - Allowed Domains

Restricts WordPress user accounts to administrator-approved email domains.

## Version

1.8.9

## Features

* Restrict WordPress user emails to approved domains
* Admin-managed allowlist
* Supports standard WordPress, REST API, and WooCommerce registrations
* Existing user audit tools
* Optional login enforcement
* Per-user unauthorized account removal
* Multisite-aware protections
* Lightweight with no custom database tables
* Short-lived audit caching for better admin performance

## Installation

1. Upload the zip file to `wp-content/plugins/`
2. Activate **Allowed Email Domains** in WordPress Admin
3. Go to **Users → Allowed Domains**
4. Add approved domains

## Example Allowlist

```text
@example.com
@company.org
@agency.net
```

## Compatibility

* WordPress 6.0+
* PHP 7.4+
* Tested on WordPress 6.9.4

## Security & Enforcement

The plugin currently includes:

* allowlist enforcement for standard WordPress registration flows
* REST API user creation/update enforcement
* WooCommerce registration enforcement
* optional login-time enforcement
* existing user audit reporting
* per-user unauthorized account deletion tools
* multisite-aware safeguards

Safety protections include:

* capability checks
* nonce verification
* confirmation prompts
* current-admin protection
* multisite Super Admin protection

Recommended operational practices:

* review the Existing User Audit before enabling login blocking
* test custom registration/SSO flows before production rollout
* maintain regular database backups before deleting users
* restrict plugin management access to trusted administrators only

## Existing User Audit

The plugin includes an audit-only report under:

```text
Users → Allowed Domains
```

The audit identifies existing users whose email domains are not currently allowed.

The audit does not automatically:

* disable users
* log users out
* modify email addresses

Unauthorized users can be reviewed individually, removed directly from the audit table, or used to quickly add their domain to the allowlist.

## Uninstall

Deleting the plugin from WordPress removes:

* `aed_allowed_domains`
* `aed_audit_log`
* `aed_block_unauthorized_logins`

On multisite, the matching network options are also removed.

## Changelog

### 1.8.9

- Updated plugin display name to improve WordPress.org naming compliance

### 1.8.7

- Packaged under the lowercase WordPress plugin slug `allowed-email-domains`
- Normalized text domain to match the lowercase plugin folder
- Removed hidden files from the distributable ZIP
- Set `Tested up to` to a Plugin Check-recognized version

### 1.8.5

- Updated package folder and text domain to lowercase format
- Matched `Tested up to` values between plugin header and `readme.txt`
- Removed hidden files from the submission package

### 1.8.4

- Updated text domain to match the current Plugin Check package slug
- Adjusted `Tested up to` value for WordPress.org readme validation
- Removed hidden files from the package
- Replaced remaining direct activation query check with sanitized input handling

### 1.8.3

- Fixed text domain and localization issues for WordPress.org checks
- Added translator comments for placeholder strings
- Removed update-specific metadata from the WordPress.org package
- Improved request sanitization for plugin check compatibility

### 1.8.2

- Prepared package for WordPress.org-style distribution
- Removed GitHub updater-specific plugin headers
- Added WordPress.org-compatible `readme.txt`
- Removed external updater documentation from the packaged README

### 1.8.x

* Added activation redirect to the Allowed Domains settings page
* Updated repository metadata for GitHub distribution

### 1.7.x

* Replaced bulk deletion with per-user delete actions
* Added quick audit actions
* Added short-lived audit caching
* Improved admin navigation and documentation access

### 1.6.x

* Added Existing User Audit
* Added login enforcement option
* Added REST API and WooCommerce enforcement
* Added unauthorized-user management tools
* Added security documentation and compatibility metadata

### 1.5.x

* Improved admin validation UX
* Added inline error messaging
* Added uninstall handling
* Improved plugin metadata and documentation

### 1.0.0

* Initial release
