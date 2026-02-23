-- Initial schema for zk-vault

CREATE TYPE backup_status AS ENUM ('pending', 'in_progress', 'completed', 'failed');

CREATE TABLE users (
    id UUID PRIMARY KEY,
    opaque_registration BYTEA NOT NULL,
    encrypted_key_store BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE source_connections (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    encrypted_tokens BYTEA NOT NULL,
    token_nonce BYTEA NOT NULL,
    sync_cursor TEXT,
    last_sync_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, source_type)
);

CREATE TABLE backup_jobs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    status backup_status NOT NULL DEFAULT 'pending',
    files_processed BIGINT NOT NULL DEFAULT 0,
    bytes_uploaded BIGINT NOT NULL DEFAULT 0,
    merkle_root BYTEA,
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE backed_up_files (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    backup_job_id UUID NOT NULL REFERENCES backup_jobs(id) ON DELETE CASCADE,
    source_file_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    original_size BIGINT NOT NULL,
    encrypted_size BIGINT NOT NULL,
    content_hash BYTEA NOT NULL,
    storage_key TEXT,
    ipfs_cid TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE anchor_receipts (
    id UUID PRIMARY KEY,
    super_root BYTEA NOT NULL,
    chain TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    block_number BIGINT,
    anchored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_backup_jobs_user_id ON backup_jobs(user_id);
CREATE INDEX idx_backup_jobs_status ON backup_jobs(status);
CREATE INDEX idx_backed_up_files_user_id ON backed_up_files(user_id);
CREATE INDEX idx_backed_up_files_backup_job_id ON backed_up_files(backup_job_id);
CREATE INDEX idx_source_connections_user_id ON source_connections(user_id);
CREATE INDEX idx_anchor_receipts_chain ON anchor_receipts(chain);
