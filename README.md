# Page Authority - Allowed Domains

Restricts WordPress user accounts to administrator-approved email domains.

## Version

1.8.15

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
* Tested on WordPress 6.9

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

### 1.8.15

- Removed redundant GitHub plugin site link from the Plugins screen

### 1.8.14

- Added GitHub plugin metadata link on the WordPress Plugins screen
- Added Page Authority author URL metadata

### 1.8.12
- Cleaned and consolidated changelog entries

### 1.8.11
- Updated WordPress.org plugin slug and text domain compatibility
- Fixed automated scan compatibility issues

### 1.8.9
- Renamed plugin to "Page Authority - Allowed Domains"

### 1.8.2
- Added unauthorized user audit tools
- Added quick actions for adding domains and deleting users

### 1.8.1
- Added login enforcement protections for unauthorized domains

### 1.8.0
- Added WooCommerce, REST API, and multisite enforcement support

### 1.7.0
- Added GitHub update compatibility support
- Improved admin navigation and documentation

### 1.6.0
- Improved validation, admin UX, and security handling

### 1.5.0
- Added uninstall cleanup and compatibility metadata

### 1.0.0
- Initial plugin release
