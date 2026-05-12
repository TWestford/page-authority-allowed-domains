# Page Authority - Allowed Domains

Restricts WordPress user accounts to administrator-approved email domains.

## Version

1.9.0

## Features

* Restrict WordPress user emails to approved domains
* Admin-managed allowlist
* Supports standard WordPress, REST API, and WooCommerce registrations
* Existing user audit tools
* Optional login enforcement
* Per-user unauthorized account removal with content reassignment
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
* per-user unauthorized account deletion tools with content reassignment
* multisite-aware safeguards

Safety protections include:

* capability checks
* nonce verification (verified before any state changes)
* confirmation prompts
* explicit content reassignment or delete confirmation before user removal
* current-admin protection
* multisite Super Admin protection
* server-side failsafe that refuses to silently delete a user's content

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

## Deleting Unauthorized Users

When deleting an unauthorized user from the audit, the plugin checks for content owned by that user (posts, pages, and other published content). If any is present, a confirmation modal lets the administrator choose:

* **Reassign all content** to another user whose email domain is on the allowlist (only compliant users appear in the dropdown), or
* **Delete the user and all their content**

If a user owns no content, deletion proceeds with a simple confirmation.

The server validates every reassignment target, refuses to silently delete content if neither option was explicitly selected, and rejects reassignment to a user whose email is not on the allowlist.

## Uninstall

Deleting the plugin from WordPress removes:

* `aed_allowed_domains`
* `aed_audit_log`
* `aed_block_unauthorized_logins`

On multisite, the matching network options are also removed.

## Changelog

### 1.9.0

- Security: nonce verification now runs before capability checks and before any input processing in the audit-domain-add and user-delete handlers
- Security: programmatic user creation in admin context (admin-ajax, importers, REST in admin) is no longer silently allowed; only the user-edit/user-new screens still defer to the inline error path
- Performance: existing-user audit query is paginated to avoid loading every user into memory on large sites
- Feature: deleting an unauthorized user who owns posts or pages now opens a confirmation modal with a dropdown of compliant users for content reassignment, or an explicit "delete content" option
- Feature: success notice when a domain is added directly from the audit
- Feature: clearer error notices for delete failures (missing user, current user, super admin, allowed-now, content-without-confirmation, invalid reassignment target)
- Hardening: server-side failsafe refuses to delete a user with owned content unless reassignment or explicit content-delete is specified (protects JS-disabled admins)
- Hardening: reassignment target is revalidated as a real, compliant user before deletion proceeds
- Cleanup: removed dead query-parameter handling, consistent `wp_unslash`-based POST input handling throughout

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
