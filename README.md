# Cloud Drive

A cloud-based online file storage system (a small Google Drive clone), built as the major project of the
Cloud Computing internship at Techn Global.

**Stack:** Flask (Python) back-end, PostgreSQL database, AWS S3 for file storage, plain HTML/CSS/JavaScript
front-end, JWT authentication, deployed on AWS EC2 behind Nginx with HTTPS.

## Features
- Register and sign in (passwords hashed, JWT tokens that expire after 12 hours)
- Upload, download, rename and delete files; create and delete folders
- **Version control:** uploading a file with the same name creates a new version; any version can be downloaded or restored
- **Sharing:** share a file with another user as *view* or *edit*; revoke at any time
- "Shared with me" page, storage meter and per-user quota (200 MB), 25 MB per-file limit
- Files are stored in a **private** S3 bucket; downloads use short-lived signed links (5 minutes)
- The server uses an **IAM role** to reach S3, so no AWS keys exist in the code

## Database (schema.sql)
| Table | Purpose |
|---|---|
| `users` | accounts (username, email, password hash) |
| `folders` | folder tree per user (`parent_id`) |
| `files` | one row per file (name, owner, folder, current version) |
| `file_versions` | file metadata: one row per version (S3 key, size, type, uploader, time) |
| `permissions` | sharing: file, user, access (`view` / `edit`) |

## API
All `/api/*` routes except register and login need the header `Authorization: Bearer <token>`.

| Method | Route | Description |
|---|---|---|
| POST | `/api/register` | create account `{username, email, password}` |
| POST | `/api/login` | sign in `{username, password}` and receive a token |
| GET | `/api/me` | current user |
| GET | `/api/list?folder=ID` | folders and files in a folder (root if omitted) |
| POST | `/api/folders` | create folder `{name, parent_id}` |
| DELETE | `/api/folders/<id>` | delete an empty folder |
| POST | `/api/files` | upload (multipart `file`, optional `folder_id` or `file_id` for a new version) |
| GET | `/api/files/<id>/download?version=N` | signed download link |
| GET | `/api/files/<id>/versions` | list versions |
| POST | `/api/files/<id>/restore` | make an older version current `{version}` |
| PATCH | `/api/files/<id>` | rename (owner) `{name}` |
| DELETE | `/api/files/<id>` | delete file and all versions (owner) |
| POST | `/api/files/<id>/share` | share `{username, access}` (owner) |
| GET | `/api/files/<id>/shares` | who has access (owner) |
| DELETE | `/api/files/<id>/share/<user_id>` | remove access (owner) |
| GET | `/api/shared` | files shared with me |
| GET | `/api/storage` | storage used and quota |
| GET | `/health` | service and database status |

## Run
Settings are read from environment variables (kept in a private `.env` file that is not in Git):
`DB_PASSWORD`, `JWT_SECRET`, `S3_BUCKET` (optional: `DB_NAME`, `DB_USER`, `AWS_REGION`, `MAX_FILE_MB`, `QUOTA_MB`).

```
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
psql -h 127.0.0.1 -U driveapp -d drivedb -f schema.sql
gunicorn --bind 127.0.0.1:8001 app:app
bash smoke_test.sh        # runs an end-to-end test with two users
```
