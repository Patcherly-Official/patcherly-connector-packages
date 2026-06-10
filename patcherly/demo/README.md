# Patcherly — Demo Mode

A self-contained mocked Errors page, surfaced in wp-admin under
**Patcherly → Demo (explore)**, so a brand-new operator can see what
Patcherly looks like *before* pairing the site for real.

## What it does

- Renders the same Errors page layout as the real plugin.
- Loads 10 fake WordPress / WooCommerce / plugin errors from the bundled
  [`demo_data.json`](demo_data.json).
- All actions (Approve, Dismiss, Rollback, Delete, bulk Delete) mutate
  state only in the browser's `sessionStorage` (per tab).
- Ships a short in-house guided tour and inline tooltips so users can
  poke around without breaking anything.
- Adds a friendly toast on every interaction so it's always clear that
  *nothing was sent anywhere*.

## What it does **not** do

This folder is held to a strict "no real I/O" contract, locked by
[`tests/test-demo-self-contained.php`](../tests/test-demo-self-contained.php):

- ❌ No `wp_remote_get` / `wp_remote_post` / `wp_remote_request` /
  `wp_remote_head` anywhere under `demo/`.
- ❌ No `fetch(ajaxurl)` / `admin-ajax.php` / `XMLHttpRequest`.
- ❌ No `update_option` / `add_option` / `update_user_meta` /
  `set_transient` / `$wpdb->` writes.
- ❌ No `localStorage` (sessionStorage is OK — it's scoped to the tab).

The only network call the demo makes is `fetch(<plugin>/demo/demo_data.json)`,
which is a bundled plugin asset served by the user's own web server.

## How to hide the demo

Operators who no longer want the **Demo (explore)** submenu in wp-admin
don't need to touch any files. Go to **Patcherly → Settings → Advanced
settings** and untick **Demo submenu** (default is ON). The submenu and
the `?page=patcherly-demo` route disappear on the next admin page load;
the demo assets stay bundled on disk but are unreachable from wp-admin.
This is controlled by the `patcherly_demo_enabled` option (`'1'`/`'0'`).


That's it — no menu entry, no enqueued assets, no orphan handles. The
rest of the plugin works unchanged because the demo never wired itself
into any of the real-state paths.

## Files

| File | Purpose |
| --- | --- |
| `demo.php` | PHP loader + `patcherly_demo_render()` + `patcherly_demo_enqueue_assets()` |
| `demo_data.json` | 10 fake errors + transition rules (single source of truth) |
| `assets/js/patcherly-demo.js` | Client-side state machine, render, actions, tour |
| `assets/css/patcherly-demo.css` | Scoped styles (toast, pills, tour overlay) |
