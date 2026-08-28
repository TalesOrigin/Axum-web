PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'reseller')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (LOWER(email));
CREATE INDEX IF NOT EXISTS users_role_idx ON users (role);

CREATE TABLE IF NOT EXISTS license_keys (
    id TEXT PRIMARY KEY NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    owner_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    max_devices INTEGER NOT NULL CHECK (max_devices > 0),
    expires_at TEXT,
    notes TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    last_verified_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS license_keys_owner_id_idx ON license_keys (owner_id);
CREATE INDEX IF NOT EXISTS license_keys_status_idx ON license_keys (status);
CREATE INDEX IF NOT EXISTS license_keys_expires_at_idx ON license_keys (expires_at);

CREATE TABLE IF NOT EXISTS device_activations (
    id TEXT PRIMARY KEY NOT NULL,
    license_id TEXT NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
    device_id_hash TEXT NOT NULL,
    device_label TEXT,
    app_id TEXT,
    app_version TEXT,
    ip_address TEXT,
    user_agent TEXT,
    last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked_at TEXT,
    UNIQUE (license_id, device_id_hash)
);

CREATE INDEX IF NOT EXISTS device_activations_license_seen_idx
    ON device_activations (license_id, last_seen_at DESC)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS license_requests (
    id TEXT PRIMARY KEY NOT NULL,
    reseller_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    max_devices INTEGER NOT NULL CHECK (max_devices > 0),
    ttl_days INTEGER NOT NULL CHECK (ttl_days > 0),
    note TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TEXT,
    admin_note TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS license_requests_reseller_idx ON license_requests (reseller_id);
CREATE INDEX IF NOT EXISTS license_requests_status_idx ON license_requests (status);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY NOT NULL,
    actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    license_id TEXT REFERENCES license_keys(id) ON DELETE SET NULL,
    request_id TEXT REFERENCES license_requests(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS audit_events_actor_idx ON audit_events (actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_license_idx ON audit_events (license_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_request_idx ON audit_events (request_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_event_type_idx ON audit_events (event_type, created_at DESC);

CREATE TRIGGER IF NOT EXISTS set_users_updated_at
AFTER UPDATE OF email, password_hash, role, is_active ON users
FOR EACH ROW
BEGIN
    UPDATE users
    SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS set_license_keys_updated_at
AFTER UPDATE OF key_prefix, key_hash, owner_id, created_by, status, max_devices,
    expires_at, notes, metadata, last_verified_at ON license_keys
FOR EACH ROW
BEGIN
    UPDATE license_keys
    SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE id = OLD.id;
END;

CREATE TRIGGER IF NOT EXISTS set_license_requests_updated_at
AFTER UPDATE OF reseller_id, quantity, max_devices, ttl_days, note, status,
    reviewed_by, reviewed_at, admin_note ON license_requests
FOR EACH ROW
BEGIN
    UPDATE license_requests
    SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    WHERE id = OLD.id;
END;
