-- Cloud Drive database schema (PostgreSQL)

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(30)  UNIQUE NOT NULL,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT         NOT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS folders (
    id         SERIAL PRIMARY KEY,
    owner_id   INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id  INT          REFERENCES folders(id) ON DELETE CASCADE,
    name       VARCHAR(255) NOT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS files (
    id              SERIAL PRIMARY KEY,
    owner_id        INT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id       INT          REFERENCES folders(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    current_version INT          NOT NULL DEFAULT 1,
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- File metadata: one row per stored version of a file
CREATE TABLE IF NOT EXISTS file_versions (
    id           SERIAL PRIMARY KEY,
    file_id      INT          NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    version_no   INT          NOT NULL,
    s3_key       TEXT         NOT NULL,
    size_bytes   BIGINT       NOT NULL,
    content_type VARCHAR(255),
    uploaded_by  INT          NOT NULL REFERENCES users(id),
    uploaded_at  TIMESTAMP    NOT NULL DEFAULT NOW(),
    UNIQUE (file_id, version_no)
);

-- Sharing: which user may open or edit which file
CREATE TABLE IF NOT EXISTS permissions (
    id         SERIAL PRIMARY KEY,
    file_id    INT         NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id    INT         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access     VARCHAR(10) NOT NULL CHECK (access IN ('view', 'edit')),
    created_at TIMESTAMP   NOT NULL DEFAULT NOW(),
    UNIQUE (file_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_files_owner_folder ON files (owner_id, folder_id);
CREATE INDEX IF NOT EXISTS idx_folders_owner_parent ON folders (owner_id, parent_id);
CREATE INDEX IF NOT EXISTS idx_permissions_user ON permissions (user_id);
