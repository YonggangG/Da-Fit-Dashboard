# DA FIT Health Dashboard

A self-hosted Docker web dashboard for DA FIT `export personal data` files.

The app lets you upload `Dafit_HealthExport_xxx.zip` exports from the DA FIT Android app, parses the JSON payload locally, stores health records in SQLite, and displays steps, heart rate, sleep, stress, monthly activity rings, import history, and account profile settings.

It is designed for local/home use and does not require root access to the Android phone.

## What's New in v0.3.0

Since v0.2.0, this release adds:

- Calendar-based navigation for reports, heart rate, sleep, metric months, and activity rings. Only dates or months with data are selectable, while navigation can still cross empty months to reach older records.
- More reliable DA FIT calendar-day mapping for travel and timezone changes, including Daily Health anchors, archive-boundary inference, sparse weather bridging, and de-duplication of competing timezone markers.
- Correct sleep-date handling using DA FIT's wake-up-day convention, plus sleep-window heart-rate averages that match DA FIT's integer truncation.
- Four compact quick-access buttons for the newest Daily Health Reports, with older reports available from the calendar.
- Clearly labeled Website Estimated Health Summaries for historical dates that do not have an exported official `daily_health_entity` report. Official DA FIT reports always take precedence.
- Stronger mobile refresh behavior and cache prevention so newly imported or restored dates appear without closing the browser tab.

See the [v0.3.0 release](https://github.com/YonggangG/Da-Fit-Dashboard/releases/tag/v0.3.0) for the complete release notes.

## Features

- Upload DA FIT personal data exports as `.zip`, `.txt`, or `.json`.
- Parse and persist these DA FIT tables:
  - `sport`: steps, distance, calories, activity minutes, step buckets.
  - `heart_rate`: daily average, min, max heart rate.
  - `sleep`: deep sleep, light sleep, REM, awake time, sleep stage detail.
  - `timing_stress`: daily stress summaries.
  - `daily_health_entity`: DA FIT daily health summary and scoring fields.
  - selected auxiliary tables such as blood oxygen, weight, water, and goals.
- Dashboard cards and charts filtered by metric month.
- Daily Health Report panel that turns DA FIT `daily_health_entity` records into a shareable text summary with score, status, goals, seven-day comparisons, and a copy button.
- A dashboard navigation shortcut and `#dailyReportCard` URL fragment jump directly to the Daily Health Report on long mobile pages.
- SVG trend charts with hover values for bars and line points.
- Daily heart-rate curve view from DA FIT's per-day `HEART_RATE` samples, with zero-value sensor dropouts shown separately.
- Sleep date selector with DA FIT-style sleep ratio, DA FIT-calibrated quality score, sleep stage timeline, sleep-window heart rate, seven-day stage trends, and reference-population comparisons.
- Monthly activity ring calendar for every month with data.
- Month-aware health suggestions.
- Authenticated CSV backup export for normalized dashboard data.
- Local username/password login with PBKDF2 password hashing and cookie sessions.
- Admin-managed accounts.
- Chinese/English UI switching; the login page is English.
- User management tab for password, default language, and health profile editing.
- Automatic health profile extraction from DA FIT `user_info` and `goals_setting`.
- Incremental import semantics so old history is not overwritten by later exports.
- Python standard library only at runtime; no pip install is required inside the image.

## Screenshots

### Login

![Login page](docs/screenshots/login-page.png)

### Dashboard

![Dashboard desktop view](docs/screenshots/dashboard-desktop.png)

### Heart Rate Trend

![Heart rate trend](docs/screenshots/heart-trend.png)

### User Management

![User management](docs/screenshots/user-management.png)

### Mobile View

![Mobile dashboard](docs/screenshots/mobile-dashboard.png)

## Quick Start with Docker

```bash
docker run -d \
  --name dafit-health-dashboard \
  --restart unless-stopped \
  -p 8088:8080 \
  -e DAFIT_ADMIN_PASSWORD='change-this-admin-password' \
  -v "$HOME/docker/dafit-health-dashboard:/data" \
  ghcr.io/yonggangg/da-fit-dashboard:latest
```

Open:

```text
http://localhost:8088/login
```

Default account:

```text
Username: admin
Password: the value of DAFIT_ADMIN_PASSWORD
```

`DAFIT_ADMIN_PASSWORD` is only used when the SQLite database creates the first `admin` user. If `/data/db/dafit_health.sqlite3` already exists, changing the environment variable will not reset the existing admin password.

## Portainer Stack Example

Create a host directory first:

```bash
mkdir -p /home/xin/docker/dafit-health-dashboard
chown -R xin:xin /home/xin/docker/dafit-health-dashboard
chmod 700 /home/xin/docker/dafit-health-dashboard
```

Paste this into Portainer Stack Editor:

```yaml
services:
  dafit-health-dashboard:
    image: ghcr.io/yonggangg/da-fit-dashboard:latest
    container_name: dafit-health-dashboard
    restart: unless-stopped
    user: "1000:1000"
    ports:
      - "8088:8080"
    environment:
      DAFIT_DATA_DIR: /data
      DAFIT_ADMIN_PASSWORD: "change-this-admin-password"
    volumes:
      - /home/xin/docker/dafit-health-dashboard:/data
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).read()"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
```

After deployment, visit:

```text
http://<docker-host-ip>:8088/login
```

## Local Build

```bash
git clone https://github.com/YonggangG/Da-Fit-Dashboard.git
cd Da-Fit-Dashboard
docker compose up --build -d
```

Then open:

```text
http://localhost:8088/login
```

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `DAFIT_DATA_DIR` | `/data` | Directory for SQLite database and uploaded export archives. |
| `DAFIT_HOST` | `0.0.0.0` | HTTP bind address inside the container. |
| `DAFIT_PORT` | `8080` | HTTP port inside the container. |
| `DAFIT_ADMIN_PASSWORD` | `change-me-admin-password` | Initial admin password for a fresh database only. |

## Input File

In the DA FIT app, use:

```text
Profile / Settings / Export personal data
```

The exported file is usually named like:

```text
Dafit_HealthExport_1784930329425.zip
```

The numeric suffix is a Unix epoch millisecond timestamp for the export generation time.

## Import Merge Policy

The current release is optimized for one watch/account, with a data model prepared for multiple users.

Repeated uploads for the same account do not replace all historical data:

- First upload imports all parseable records.
- Later uploads append records newer than the database's latest `sport` day.
- Dates older than the database's latest `sport` day are preserved.
- The database's previous latest day is replaced only if the new ZIP has a higher same-day `sport.STEPS` value.
- If same-day steps are not higher, that day is skipped and old records are preserved.
- `daily_health_entity` reports are merged independently by their own `DISPLAY_DATE`; refreshing same-day activity metrics never deletes an earlier Daily Health Report.

This fits DA FIT's partial same-day sync behavior: exporting again later in the day can improve today's record without rewriting old history.

## DA FIT Data Semantics

- Sleep dates match the DA FIT Sleep screen: a night is labeled by its wake-up day. The exported sleep `date_ms` already carries that DA FIT calendar day (including local-midnight UTC offsets), so the dashboard preserves its calendar date instead of subtracting a day. The database keeps the original timestamp, and `/api/summary` also exposes it as `archive_date_iso`.

DA FIT exports contain more than one steps field:

- `sport.STEPS`: closest to the DA FIT Steps page and used as the dashboard's primary steps value.
- `daily_health_entity.STEPS_VALUE`: DA FIT daily health/scoring summary; it may differ from the Steps page.

The steps summary card, steps trend, activity calendar, and step-based advice use `sport.STEPS`, matching the DA FIT Steps screen. Other summary metrics can use the selected `daily_health_entity` report's fixed heart-rate, sleep, and stress values; if no Daily Report exists, they fall back to the normalized records.

Selecting an older date in the Daily Health Report dropdown also updates the summary cards and health advice to that report's snapshot, so historical reports such as August 2 remain directly comparable with the DA FIT app.

Dashboard month and health-record date navigation uses calendar grids instead of long dropdown lists. Dates/months that contain data are selectable; gaps are rendered gray and disabled. Date calendars can still navigate across a completely empty month to reach older data on the other side. The Daily Health Report also keeps four quick buttons for the most recent four report dates; older reports remain reachable through its calendar.

Dashboard HTML and JSON responses use `Cache-Control: no-store` so a browser or reverse proxy does not keep an older inline-JavaScript version after the container is rebuilt.

The dashboard also requests `/api/summary` with an explicit cache-busting query and refreshes visible pages when they regain focus, return from the browser back/forward cache, or remain open. An already-open mobile tab therefore picks up newly restored or imported report dates without needing to be closed manually.

DA FIT day fields are calendar dates, not browser-local instants. The dashboard therefore renders the `YYYY-MM-DD` portion of normalized records directly (and raw report-day timestamps by their UTC calendar components) instead of converting them through the phone's timezone. This prevents an August 2 report from being mislabeled August 1 on phones set to a western timezone.

Monthly activity progress uses an SVG circle with an explicit 0–100 stroke length rather than a CSS conic gradient. This keeps a 63% day visibly beyond half a circle on mobile browsers that render gradient stops inconsistently.

Trend charts and the sleep/heart detail date pickers show one record per DA FIT calendar day. When a unique `daily_health_entity` steps/calories pair matches a `sport` row, its report date (which describes the preceding activity day) is the strongest calendar anchor. This handles travel exports where a full-day sport record can be written at `07:00 UTC` yet still belong to that UTC calendar date in the DA FIT app. Otherwise, DA FIT archives a completed `sport` day at the following local-midnight boundary: for a near-exact hour-boundary row (minute 00–02) with complete 30-minute activity bins, the dashboard infers the historical UTC offset and displays the archive on the preceding local day. Boundary-timed rows without complete bins and other non-boundary snapshots stay on their exported day. When multiple normalized snapshots land on one local day, steps keep the latest timestamped snapshot. Raw imported rows and timestamps remain unchanged in the database for auditability.

The monthly activity calendar compares consecutive completed archives. When the inferred historical offset changes, that activity day's ring and day number turn orange. For a current/realtime day that has no completed archive yet, nearby actual (non-forecast) DA FIT weather records can bridge a gap of up to seven days: the first activity day after the last observation in the old zone is marked as the transition activity day. The one-week allowance handles sparse weather history in a fresh export (for example, an August 2 Eastern observation followed by an August 6 Pacific observation still marks August 3); larger gaps are ignored to avoid inventing travel transitions from stale location records. When a weather-based transition is available, it takes precedence over nearby archive-offset changes so the same trip is not marked orange on two consecutive days. Hover text shows the previous and new location labels and offsets, including US Pacific, US Eastern, China, and Korea; uncommon offsets fall back to a generic `UTC±N` label.

Daily heart-rate curves use the raw `heart_rate.HEART_RATE` array from each DA FIT daily heart-rate record. Values above zero are drawn as the heart-rate line; zero values are treated as missing sensor readings and are shown as bottom markers rather than real heart-rate measurements.

Sleep quality is calculated from the selected `sleep` record instead of the DA FIT `daily_health_entity` aggregate score. DA FIT does not include the app's sleep-quality score in the exported sleep table, so the dashboard uses a wearable-data approximation inspired by PSQI principles: total sleep duration, deep-plus-REM share, seven-night sleep/wake-time regularity, awake-segment count, and awake minutes. Exact phase-duration tuples from the supplied DA FIT screenshots are calibration anchors (1h37m = 19, 6h09m = 82, 6h53m = 88, 7h02m = 91, 7h22m = 100, and 8h21m = 100); other nights use the general approximation.

The sleep-ratio card follows the DA FIT app's three-category display exactly: `DEEP` is Deep sleep, `SHALLOW` is Light sleep, and `REM` is REM. Their exported minute values are shown without redistribution, and their sum is the card total. `SOBER` represents awake/interruption time, so it remains available to the sleep-stage timeline and quality calculation but is intentionally excluded from the ratio list, donut, and total.

Sleep-window heart rate is derived by selecting the nearest exported daily heart record and retaining its 10-minute samples that fall between the selected sleep record's first and last stage times. The displayed average follows DA FIT's integer truncation, while minimum/maximum use the available samples; all three can be incomplete when the current day's export was generated before all heart samples synchronized. The seven-day sleep trend uses the same deduplicated Deep/Light/REM records as the sleep selector.

The comparison cards are transparent local estimates for bedtime, wake time, and sleep duration. DA FIT exports do not contain the app server's age/sex cohort distribution or official comparison percentiles, so the dashboard labels these as reference-population estimates and does not claim they are live DA FIT cohort data.

This 0–100 daily score is not the clinical PSQI. The official PSQI is a 19-item self-report assessment covering one month; its seven component scores range from 0 to 3 and sum to a 0–21 global score where higher is worse. The dashboard only borrows its multidimensional principles because the DA FIT export cannot provide subjective quality, medication use, or daytime dysfunction. References: [University of Pittsburgh PSQI overview and scoring](https://www.sleep.pitt.edu/psqi) and [University of Pittsburgh measures and instruments](https://www.sleep.pitt.edu/research/measures-and-study-instruments).

The Daily Health Report panel is generated from DA FIT's `daily_health_entity` rows. Each selectable report keeps DA FIT's own `TOTAL_SCORE`, `GRADE`, metric goals, metric statuses, report date, and generated timestamp, then enriches the text with seven-day averages from the normalized dashboard tables where available. The copy button copies the generated report text for posting elsewhere.

DA FIT exports only the latest `daily_health_entity`, so dates without a preserved official report receive a clearly labeled **Website estimate** when at least one normalized metric is available. The estimate combines only available values: steps (35% target weight), sleep duration (30%), heart-rate range (15%), and stress (20%), then renormalizes the weights when a metric is missing. Calories may be displayed when present but are not scored separately. Official DA FIT rows always take precedence for the same date, and estimated cards/text never claim an official DA FIT grade, generation time, or sleep-quality score.

DA FIT's raw `ATTENTION` grade is displayed as `Needs Improvement (ATTENTION)` so the dashboard matches the wording shown in the app while preserving the exported status code.

## User Profile Rules

When a ZIP is uploaded, the app extracts health profile fields for the current logged-in user:

- From `user_info`: height, weight, birthday, gender, step length.
- From `goals_setting`: daily steps goal, calorie goal, activity minutes goal.
- A readable device name when available.

The app intentionally does not show device MAC addresses, Bluetooth addresses, notification tokens, or bond codes in the user management page.

`BIRTHDAY` is used for birthday. `BIRTH_YEAR` is not imported automatically; the Birth Year field remains available for manual editing.

## Security Notes

- This is a local self-hosted dashboard, intended for trusted home/LAN use.
- Passwords are stored as PBKDF2 hashes in SQLite.
- Session cookies are local HTTP cookies with `HttpOnly` and `SameSite=Lax`.
- CSV backup exports require login and intentionally exclude the `users` and `sessions` tables.
- Uploaded DA FIT archives may contain personal health information and device metadata. Keep the `/data` volume private.
- Health suggestions are simple lifestyle observations based on uploaded data. They are not medical advice.

## Release Image

Container images are published to GitHub Container Registry:

```text
ghcr.io/yonggangg/da-fit-dashboard:latest
ghcr.io/yonggangg/da-fit-dashboard:v0.2.0
ghcr.io/yonggangg/da-fit-dashboard:v0.1.0
```

## License

MIT License. See [LICENSE](LICENSE).
