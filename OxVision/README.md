# OxVision

Flask + D3.js control panel for visualizing port-scan JSON results with SQLite persistence.

## Run

cd Backend
pip install -r ../Configurations/requirements.txt
python app.py

Open `http://<server-ip>:5000` from another device on the network.

## Authentication

Every page and API route requires a signed-in account. On first launch a super admin
account is seeded automatically from environment variables:

- `OXVISUAL_SECRET_KEY` (required; use a long random value)
- `OXVISUAL_SUPERADMIN_USER` (default `admin`)
- `OXVISUAL_SUPERADMIN_PASSWORD` (required)
- `OXVISUAL_SUPERADMIN_EMAIL` (default `superadmin@oxvisual.local`)
- `OXVISUAL_CORS_ORIGINS` (default `http://127.0.0.1:5000`)
- `OXVISUAL_HOST` (default `0.0.0.0`; listens on all network interfaces)
- `OXVISUAL_PORT` (default `5000`)

Set the required values in the project root `.env` file. The application exits at
startup when either required secret is missing. See `.env.example` for the required
format. Do not commit `.env` or share its values.

Roles are `viewer`, `analyst`, `operator`, `manager`, `user`, `admin`, and `super_admin`.
Viewer accounts can only view Dashboard, Network Graph, and Hosts. Analysts can also
edit host notes and roles. Operators additionally have upload access. Managers can open
`/admincpanel` and change roles for non-administrative users in their own team, but
cannot create, disable, delete, or manage `admin` or `super_admin` accounts. Only
`super_admin` can create accounts and perform full account administration.

Login issues two HttpOnly cookies:

- `oxtoken` - JWT access token, 1 hour lifetime, carries `user_id` and `role`.
- `oxrefresh` - JWT refresh token, 7 day lifetime, used to silently reissue `oxtoken`.

Five consecutive failed logins lock the account for 15 minutes. Login requests are
rate-limited to 10 per minute per IP. Passwords are hashed with bcrypt.

By default cookies are not marked `Secure` so the app also works over plain HTTP in
local development. Set `OXVISUAL_ENV=production` to serve this behind HTTPS and enable
`Secure` cookies. `python app.py` serves the application with Waitress.

## Usage

1. Go to Upload, select a port-scan JSON file (hosts/ports/subnets format).
2. Dashboard shows host/port stats.
3. Network Graph renders hosts and shared ports as a force-directed D3 graph.
4. Hosts shows a full table of every host and its open ports.
5. Administrators can use Dashboard > Reset (the administrator password is required). Reset never deletes data: the current `portscan.db` is renamed to `portscan_{id}.db.bak`, a fresh database is created, and user accounts are carried over to it.

Uploaded JSON results are imported into `uploads/portscan.db`. The database is the
canonical source for all views and edits. Existing JSON files are imported
automatically on the first startup after this migration.

## Backups and snapshots

Super admins see two extra sections in `/admincpanel`:

- **Snapshots** - create a point-in-time copy of the current database with an optional label, restore it later, or delete it. Snapshots are stored in `uploads/snapshots/`.
- **Database backups** - lists every archived database in `uploads/` (`portscan_{id}.db.bak` files created by Reset and restores, plus manually copied `.db` files) and lets you restore any of them.

Restoring replaces the scan data and subnet names with the selected file and requires the administrator password. User accounts are never changed by a restore. The current data is archived as a new `portscan_{id}.db.bak` before every restore, so nothing is lost.

## Bytecode cache

All Python bytecode loaded by the application is written to the `PyCache` folder in the
project root instead of `__pycache__` folders next to the source files. This is configured
before application imports in `Backend/app.py`.

## Roles

Every host can have up to 8 roles (Domain Controller, Web Server, Database, custom roles, ...).
Operators and administrators can edit hostname, operating system, and roles from the
Network Graph by right-clicking a host and selecting Edit. Analysts can edit roles and
notes. Roles and host details are stored in the SQLite database. Manager accounts
require a team value and are scoped to that team.

## Sort & Filter

The left sidebar filters and sorts every view (Dashboard, Graph, Hosts) at once: free-text search,
OS, roles, ports (`22, 445, 8000-8100, 53/udp`), service, minimum open ports, and sort order.
Dashboard charts are clickable and apply the same filters.