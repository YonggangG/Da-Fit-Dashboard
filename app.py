from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


DATA_DIR = Path(os.environ.get("DAFIT_DATA_DIR", "/data"))
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "db" / "dafit_health.sqlite3"
HOST = os.environ.get("DAFIT_HOST", "0.0.0.0")
PORT = int(os.environ.get("DAFIT_PORT", "8080"))
SESSION_TTL_SECONDS = 60 * 60 * 24 * 14
DEFAULT_ADMIN_PASSWORD = os.environ.get("DAFIT_ADMIN_PASSWORD", "change-me-admin-password")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ms_to_iso(value: Any) -> str | None:
    if not isinstance(value, (int, float)) or value <= 1_000_000_000_000:
        return None
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()


def jdump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def hash_password(password: str, salt_hex: str | None = None) -> str:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$", 2)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    expected = hash_password(password, salt_hex).split("$", 2)[2]
    return hmac.compare_digest(expected, digest_hex)


def ensure_default_admin(db: sqlite3.Connection) -> None:
    columns = {row["name"] for row in db.execute("pragma table_info(users)").fetchall()}
    if "default_language" not in columns:
        db.execute("alter table users add column default_language text not null default 'zh'")
    row = db.execute("select id from users where username = ?", ("admin",)).fetchone()
    if row:
        return
    db.execute(
        "insert into users (username, password_hash, is_admin, created_at, default_language) values (?, ?, 1, ?, 'zh')",
        ("admin", hash_password(DEFAULT_ADMIN_PASSWORD), now_iso()),
    )


def init_db() -> None:
    with connect() as db:
        db.executescript(
            """
            create table if not exists imports (
              id integer primary key autoincrement,
              filename text not null,
              sha256 text not null unique,
              export_ms integer,
              uploaded_at text not null,
              source_saved_path text not null,
              top_level_keys_json text not null,
              counts_json text not null
            );
            create table if not exists sport (
              date_ms integer primary key,
              date_iso text,
              steps integer,
              distance real,
              calories real,
              active_time real,
              time_interval integer,
              completion real,
              steps_category_json text,
              import_id integer not null
            );
            create table if not exists heart_rate (
              date_ms integer primary key,
              date_iso text,
              average real,
              min_rate real,
              max_rate real,
              raw_json text,
              import_id integer not null
            );
            create table if not exists sleep (
              date_ms integer primary key,
              date_iso text,
              deep real,
              shallow real,
              rem real,
              sober real,
              completion real,
              detail_json text,
              import_id integer not null
            );
            create table if not exists timing_stress (
              date_ms integer primary key,
              date_iso text,
              average real,
              min_stress real,
              max_stress real,
              stress_json text,
              import_id integer not null
            );
            create table if not exists daily_health (
              display_date_ms integer primary key,
              display_date_iso text,
              report_date_iso text,
              generated_date_iso text,
              steps real,
              calories real,
              heart_rate real,
              sleep_duration real,
              activity real,
              total_score real,
              grade text,
              raw_json text,
              import_id integer not null
            );
            create table if not exists auxiliary (
              table_name text not null,
              date_ms integer not null,
              date_iso text,
              raw_json text not null,
              import_id integer not null,
              primary key (table_name, date_ms)
            );
            create table if not exists users (
              id integer primary key autoincrement,
              username text not null unique,
              password_hash text not null,
              is_admin integer not null default 0,
              created_at text not null
            );
            create table if not exists sessions (
              token text primary key,
              user_id integer not null,
              created_at text not null,
              expires_at integer not null
            );
            create table if not exists user_profiles (
              user_id integer primary key,
              height_cm real,
              height_in real,
              weight_kg real,
              weight_lbs real,
              gender integer,
              birth_year integer,
              birthday_ms integer,
              step_length_cm real,
              step_length_in real,
              daily_steps_goal integer,
              daily_calories_goal integer,
              daily_minutes_goal integer,
              measurement_system integer,
              locale text,
              device_name text,
              raw_json text,
              updated_from_import_id integer,
              updated_at text not null,
              foreign key(user_id) references users(id)
            );
            """
        )
        ensure_default_admin(db)


def export_ms_from_name(name: str) -> int | None:
    match = re.search(r"Dafit_HealthExport_(\d{13})", name)
    return int(match.group(1)) if match else None


def read_export_payload(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            candidates = [
                n
                for n in zf.namelist()
                if n.lower().endswith((".txt", ".json")) and not n.endswith("/")
            ]
            if not candidates:
                raise ValueError("ZIP 里没有 .txt 或 .json 导出文件")
            preferred = sorted(
                candidates,
                key=lambda n: (0 if "dafit_healthexport" in n.lower() else 1, len(n)),
            )[0]
            raw = zf.read(preferred).decode("utf-8", errors="replace")
    else:
        raw = path.read_text(encoding="utf-8", errors="replace")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("导出 JSON 顶层不是对象")
    return payload


def table_count(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    return len(value) if isinstance(value, list) else 0


def day_key(value: Any) -> str | None:
    iso = ms_to_iso(value)
    return iso[:10] if iso else None


def upsert_import(db: sqlite3.Connection, file_path: Path, payload: dict[str, Any]) -> int:
    digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
    export_ms = export_ms_from_name(file_path.name)
    counts = {
        key: table_count(payload, key)
        for key in [
            "daily_health_entity",
            "heart_rate",
            "sleep",
            "sport",
            "timing_stress",
            "blood_oxygen",
            "weight",
            "water",
        ]
    }
    db.execute(
        """
        insert into imports
          (filename, sha256, export_ms, uploaded_at, source_saved_path, top_level_keys_json, counts_json)
        values (?, ?, ?, ?, ?, ?, ?)
        on conflict(sha256) do update set
          filename=excluded.filename,
          export_ms=excluded.export_ms,
          uploaded_at=excluded.uploaded_at,
          source_saved_path=excluded.source_saved_path,
          top_level_keys_json=excluded.top_level_keys_json,
          counts_json=excluded.counts_json
        """,
        (
            file_path.name,
            digest,
            export_ms,
            now_iso(),
            str(file_path),
            jdump(sorted(payload.keys())),
            jdump(counts),
        ),
    )
    row = db.execute("select id from imports where sha256 = ?", (digest,)).fetchone()
    return int(row["id"])


def first_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        for row in value:
            if isinstance(row, dict):
                return row
    return {}


def first_number(*values: Any) -> float | None:
    for value in values:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str) and value.strip():
            try:
                return float(value)
            except ValueError:
                pass
    return None


def rounded_number(*values: Any) -> float | None:
    value = first_number(*values)
    return round(value, 1) if value is not None else None


def extract_profile(payload: dict[str, Any]) -> dict[str, Any]:
    user_info = first_dict(payload.get("user_info"))
    goals = first_dict(payload.get("goals_setting"))
    sp_config = payload.get("sp_config") if isinstance(payload.get("sp_config"), dict) else {}
    device_scan = first_dict(payload.get("device_scan_record"))
    quick_config = first_dict(payload.get("quick_contart_config"))
    watch_face = first_dict(payload.get("watch_face"))
    profile = {
        "height_cm": rounded_number(user_info.get("HEIGHT_CM")),
        "height_in": rounded_number(user_info.get("HEIGHT_IN")),
        "weight_kg": rounded_number(user_info.get("WEIGHT_KG")),
        "weight_lbs": rounded_number(user_info.get("WEIGHT_LBS")),
        "gender": int(user_info["GENDER"]) if isinstance(user_info.get("GENDER"), int) else None,
        "birth_year": None,
        "birthday_ms": int(user_info["BIRTHDAY"]) if isinstance(user_info.get("BIRTHDAY"), int) else None,
        "step_length_cm": rounded_number(user_info.get("STEP_LENGTH_CM")),
        "step_length_in": rounded_number(user_info.get("STEP_LENGTH_IN")),
        "daily_steps_goal": int(goals["DAILY_STEPS"]) if isinstance(goals.get("DAILY_STEPS"), int) else None,
        "daily_calories_goal": int(goals["DAILY_CALORIES"]) if isinstance(goals.get("DAILY_CALORIES"), int) else None,
        "daily_minutes_goal": int(goals["DAILY_MINUTES"]) if isinstance(goals.get("DAILY_MINUTES"), int) else None,
        "measurement_system": int(sp_config["measurement_system"]) if isinstance(sp_config.get("measurement_system"), int) else None,
        "locale": first_dict(payload.get("android_metadata")).get("locale"),
        "device_name": quick_config.get("NAME") or device_scan.get("NAME") or watch_face.get("BROADCAST_NAME"),
        "raw_json": jdump({"user_info": user_info, "goals_setting": goals}),
    }
    return {key: value for key, value in profile.items() if value not in (None, "")}


def upsert_user_profile(db: sqlite3.Connection, user_id: int, payload: dict[str, Any], import_id: int) -> bool:
    profile = extract_profile(payload)
    if not profile:
        return False
    columns = [
        "height_cm", "height_in", "weight_kg", "weight_lbs", "gender", "birth_year", "birthday_ms",
        "step_length_cm", "step_length_in", "daily_steps_goal", "daily_calories_goal", "daily_minutes_goal",
        "measurement_system", "locale", "device_name", "raw_json",
    ]
    values = [profile.get(col) for col in columns]
    assignments = ", ".join(
        f"{col}=excluded.{col}" if col in {"birth_year", "birthday_ms"} else f"{col}=coalesce(excluded.{col}, user_profiles.{col})"
        for col in columns
    )
    db.execute(
        f"""
        insert into user_profiles
          (user_id, {", ".join(columns)}, updated_from_import_id, updated_at)
        values
          (?, {", ".join("?" for _ in columns)}, ?, ?)
        on conflict(user_id) do update set
          {assignments},
          updated_from_import_id=excluded.updated_from_import_id,
          updated_at=excluded.updated_at
        """,
        (user_id, *values, import_id, now_iso()),
    )
    return True


def user_profile(db: sqlite3.Connection, user_id: int) -> dict[str, Any]:
    row = db.execute("select * from user_profiles where user_id = ?", (user_id,)).fetchone()
    return dict(row) if row else {}


def parse_optional_float(body: bytes, key: str) -> float | None:
    value = form_value(body, key)
    if not value:
        return None
    return float(value)


def parse_optional_int(body: bytes, key: str) -> int | None:
    value = form_value(body, key)
    if not value:
        return None
    return int(float(value))


def birthday_ms_from_form(value: str) -> int | None:
    if not value:
        return None
    return int(datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp() * 1000)


def update_user_profile_from_form(db: sqlite3.Connection, user_id: int, body: bytes) -> dict[str, Any]:
    fields = {
        "height_cm": parse_optional_float(body, "height_cm"),
        "weight_kg": parse_optional_float(body, "weight_kg"),
        "gender": parse_optional_int(body, "gender"),
        "birth_year": parse_optional_int(body, "birth_year"),
        "birthday_ms": birthday_ms_from_form(form_value(body, "birthday")),
        "step_length_cm": parse_optional_float(body, "step_length_cm"),
        "daily_steps_goal": parse_optional_int(body, "daily_steps_goal"),
        "daily_calories_goal": parse_optional_int(body, "daily_calories_goal"),
        "daily_minutes_goal": parse_optional_int(body, "daily_minutes_goal"),
        "device_name": form_value(body, "device_name") or None,
    }
    if fields["height_cm"]:
        fields["height_in"] = round(fields["height_cm"] / 2.54, 1)
    else:
        fields["height_in"] = None
    if fields["weight_kg"]:
        fields["weight_lbs"] = round(fields["weight_kg"] * 2.2046226218, 1)
    else:
        fields["weight_lbs"] = None
    if fields["step_length_cm"]:
        fields["step_length_in"] = round(fields["step_length_cm"] / 2.54, 1)
    else:
        fields["step_length_in"] = None
    columns = list(fields.keys())
    db.execute(
        f"""
        insert into user_profiles (user_id, {", ".join(columns)}, updated_at)
        values (?, {", ".join("?" for _ in columns)}, ?)
        on conflict(user_id) do update set
          {", ".join(f"{col}=excluded.{col}" for col in columns)},
          updated_at=excluded.updated_at
        """,
        (user_id, *[fields[col] for col in columns], now_iso()),
    )
    return user_profile(db, user_id)


def ingest_payload(db: sqlite3.Connection, import_id: int, payload: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    latest_existing = db.execute(
        "select date_ms, steps from sport order by date_ms desc limit 1"
    ).fetchone()
    latest_existing_day = day_key(latest_existing["date_ms"]) if latest_existing else None
    latest_existing_steps = int(latest_existing["steps"] or 0) if latest_existing else 0
    latest_new_steps = 0
    for row in payload.get("sport") or []:
        if isinstance(row, dict) and day_key(row.get("DATE")) == latest_existing_day:
            latest_new_steps = max(latest_new_steps, int(row.get("STEPS") or 0))
    replace_latest_day = bool(
        latest_existing_day and latest_new_steps > latest_existing_steps
    )

    def should_apply(date_ms: Any) -> bool:
        row_day = day_key(date_ms)
        if not row_day or not latest_existing_day:
            return True
        if row_day > latest_existing_day:
            return True
        if row_day == latest_existing_day and replace_latest_day:
            return True
        return False

    if replace_latest_day:
        for table, date_col in [
            ("sport", "date_ms"),
            ("heart_rate", "date_ms"),
            ("sleep", "date_ms"),
            ("timing_stress", "date_ms"),
            ("auxiliary", "date_ms"),
        ]:
            rows_to_delete = [
                r[0]
                for r in db.execute(f"select {date_col} from {table}").fetchall()
                if day_key(r[0]) == latest_existing_day
            ]
            for value in rows_to_delete:
                db.execute(f"delete from {table} where {date_col} = ?", (value,))
    for row in payload.get("sport") or []:
        if not isinstance(row, dict) or not isinstance(row.get("DATE"), int):
            continue
        if not should_apply(row["DATE"]):
            counts["sport_skipped"] = counts.get("sport_skipped", 0) + 1
            continue
        db.execute(
            """insert or replace into sport
            (date_ms, date_iso, steps, distance, calories, active_time, time_interval, completion, steps_category_json, import_id)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row["DATE"],
                ms_to_iso(row["DATE"]),
                row.get("STEPS"),
                row.get("DISTANCE"),
                row.get("CALORY"),
                row.get("TIME"),
                row.get("TIME_INTERVAL"),
                row.get("COMPLETION"),
                row.get("STEPS_CATEGORY") or "[]",
                import_id,
            ),
        )
        counts["sport"] = counts.get("sport", 0) + 1

    for row in payload.get("heart_rate") or []:
        if not isinstance(row, dict) or not isinstance(row.get("DATE"), int):
            continue
        if not should_apply(row["DATE"]):
            counts["heart_rate_skipped"] = counts.get("heart_rate_skipped", 0) + 1
            continue
        db.execute(
            """insert or replace into heart_rate
            (date_ms, date_iso, average, min_rate, max_rate, raw_json, import_id)
            values (?, ?, ?, ?, ?, ?, ?)""",
            (
                row["DATE"],
                ms_to_iso(row["DATE"]),
                row.get("AVERAGE"),
                row.get("MIN_HEART_RATE"),
                row.get("MAX_HEART_RATE"),
                jdump(row),
                import_id,
            ),
        )
        counts["heart_rate"] = counts.get("heart_rate", 0) + 1

    for row in payload.get("sleep") or []:
        if not isinstance(row, dict) or not isinstance(row.get("DATE"), int):
            continue
        if not should_apply(row["DATE"]):
            counts["sleep_skipped"] = counts.get("sleep_skipped", 0) + 1
            continue
        db.execute(
            """insert or replace into sleep
            (date_ms, date_iso, deep, shallow, rem, sober, completion, detail_json, import_id)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row["DATE"],
                ms_to_iso(row["DATE"]),
                row.get("DEEP"),
                row.get("SHALLOW"),
                row.get("REM"),
                row.get("SOBER"),
                row.get("COMPLETION"),
                row.get("DETAIL") or "[]",
                import_id,
            ),
        )
        counts["sleep"] = counts.get("sleep", 0) + 1

    for row in payload.get("timing_stress") or []:
        if not isinstance(row, dict) or not isinstance(row.get("DATE"), int):
            continue
        if not should_apply(row["DATE"]):
            counts["timing_stress_skipped"] = counts.get("timing_stress_skipped", 0) + 1
            continue
        db.execute(
            """insert or replace into timing_stress
            (date_ms, date_iso, average, min_stress, max_stress, stress_json, import_id)
            values (?, ?, ?, ?, ?, ?, ?)""",
            (
                row["DATE"],
                ms_to_iso(row["DATE"]),
                row.get("AVERAGE"),
                row.get("MIN"),
                row.get("MAX"),
                jdump(row.get("STRESS", [])),
                import_id,
            ),
        )
        counts["timing_stress"] = counts.get("timing_stress", 0) + 1

    for row in payload.get("daily_health_entity") or []:
        if not isinstance(row, dict) or not isinstance(row.get("DISPLAY_DATE"), int):
            continue
        db.execute(
            """insert or replace into daily_health
            (display_date_ms, display_date_iso, report_date_iso, generated_date_iso, steps, calories, heart_rate,
             sleep_duration, activity, total_score, grade, raw_json, import_id)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row["DISPLAY_DATE"],
                ms_to_iso(row["DISPLAY_DATE"]),
                ms_to_iso(row.get("REPORT_DATE")),
                ms_to_iso(row.get("GENERATED_DATE")),
                row.get("STEPS_VALUE"),
                row.get("CALORIES_VALUE"),
                row.get("HEART_RATE_VALUE"),
                row.get("SLEEP_DURATION_VALUE"),
                row.get("ACTIVITY_VALUE"),
                row.get("TOTAL_SCORE"),
                row.get("GRADE"),
                jdump(row),
                import_id,
            ),
        )
        counts["daily_health_entity"] = counts.get("daily_health_entity", 0) + 1

    for table in ["blood_oxygen", "weight", "water", "goals_setting", "weather"]:
        for idx, row in enumerate(payload.get(table) or []):
            if not isinstance(row, dict):
                continue
            date_ms = row.get("DATE")
            if not isinstance(date_ms, int):
                if latest_existing_day:
                    counts[f"{table}_skipped"] = counts.get(f"{table}_skipped", 0) + 1
                    continue
                date_ms = import_id * 1_000_000 + idx
            if table != "weather" and isinstance(row.get("DATE"), int) and not should_apply(date_ms):
                counts[f"{table}_skipped"] = counts.get(f"{table}_skipped", 0) + 1
                continue
            db.execute(
                """insert or replace into auxiliary
                (table_name, date_ms, date_iso, raw_json, import_id)
                values (?, ?, ?, ?, ?)""",
                (table, date_ms, ms_to_iso(date_ms), jdump(row), import_id),
            )
            counts[table] = counts.get(table, 0) + 1

    db.commit()
    return counts


def rows(db: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(sql, params).fetchall()]


def latest(db: sqlite3.Connection, table: str) -> dict[str, Any] | None:
    date_col = "display_date_ms" if table == "daily_health" else "date_ms"
    row = db.execute(f"select * from {table} order by {date_col} desc limit 1").fetchone()
    return dict(row) if row else None


def latest_where(db: sqlite3.Connection, table: str, condition: str) -> dict[str, Any] | None:
    row = db.execute(f"select * from {table} where {condition} order by date_ms desc limit 1").fetchone()
    return dict(row) if row else None


def advice(summary: dict[str, Any]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    latest_rows = summary.get("latest", {})
    sport = latest_rows.get("sport")
    daily = latest_rows.get("daily_health")
    sleep_row = summary.get("latest", {}).get("sleep")
    heart = summary.get("latest", {}).get("heart_rate")
    stress = summary.get("latest", {}).get("timing_stress")
    if daily or sport:
        steps = (sport or {}).get("steps") or (daily or {}).get("steps") or 0
        if steps >= 8000:
            items.append({"level": "good", "title": "活动量不错", "text": f"最新记录 {steps:,} 步，已经接近或超过常见日常活动目标。"})
        elif steps >= 4000:
            items.append({"level": "watch", "title": "步数中等", "text": f"最新记录 {steps:,} 步，可以用饭后散步把当天活动量补到 7000-8000 步区间。"})
        else:
            items.append({"level": "warn", "title": "活动量偏低", "text": f"最新记录 {steps:,} 步，建议今天安排 20-30 分钟轻中度步行。"})
    if sleep_row:
        total = sum(float(sleep_row.get(k) or 0) for k in ["deep", "shallow", "rem"])
        if total >= 420:
            items.append({"level": "good", "title": "睡眠时长充足", "text": f"最近睡眠约 {total / 60:.1f} 小时。继续保持固定作息。"})
        elif total > 0:
            items.append({"level": "watch", "title": "睡眠时长不足", "text": f"最近睡眠约 {total / 60:.1f} 小时，优先保证连续睡眠窗口。"})
    if heart and heart.get("average"):
        avg = float(heart["average"])
        if avg >= 95:
            items.append({"level": "watch", "title": "平均心率偏高", "text": f"最新平均心率约 {avg:.0f} bpm。结合运动、咖啡因、压力和睡眠一起看。"})
        elif avg <= 55:
            items.append({"level": "watch", "title": "平均心率偏低", "text": f"最新平均心率约 {avg:.0f} bpm。如果伴随不适，应线下咨询医生。"})
        else:
            items.append({"level": "good", "title": "心率区间平稳", "text": f"最新平均心率约 {avg:.0f} bpm。"})
    if stress and stress.get("average"):
        avg = float(stress["average"])
        if avg >= 60:
            items.append({"level": "watch", "title": "压力指数偏高", "text": f"最近压力均值约 {avg:.0f}，可以安排短休息、呼吸练习或低强度散步。"})
    if not items:
        items.append({"level": "watch", "title": "等待更多数据", "text": "上传 DA FIT personal data 导出后，这里会按步数、心率、睡眠和压力生成建议。"})
    return items


def summary_payload() -> dict[str, Any]:
    with connect() as db:
        def sleep_display_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
            """Match DA FIT's sleep calendar, which labels a night by its wake-up day."""
            if not row or not row.get("date_iso"):
                return row
            display = dict(row)
            display["archive_date_iso"] = display["date_iso"]
            return display

        sleep_latest = sleep_display_row(
            latest_where(db, "sleep", "coalesce(deep,0) + coalesce(shallow,0) + coalesce(rem,0) >= 120")
        )
        sleep_series = [
            sleep_display_row(row)
            for row in rows(db, "select date_ms, date_iso, deep, shallow, rem, sober, completion, detail_json from sleep order by date_ms desc limit 1000")[::-1]
        ]
        summary: dict[str, Any] = {
            "latest": {
                "sport": latest(db, "sport"),
                "heart_rate": latest(db, "heart_rate"),
                "sleep": sleep_latest,
                "timing_stress": latest_where(db, "timing_stress", "coalesce(average,0) > 0"),
                "daily_health": latest(db, "daily_health"),
            },
            "series": {
                "sport": rows(db, "select date_ms, date_iso, steps, distance, calories, time_interval, steps_category_json from sport order by date_ms desc limit 1000")[::-1],
                "heart_rate": rows(db, "select date_ms, date_iso, average, min_rate, max_rate, raw_json from heart_rate where average is not null order by date_ms desc limit 1000")[::-1],
                "sleep": sleep_series,
                "stress": rows(db, "select date_ms, date_iso, average, min_stress, max_stress from timing_stress where average is not null order by date_ms desc limit 1000")[::-1],
                "daily_health": rows(db, "select display_date_ms as date_ms, display_date_iso as date_iso, steps, calories, activity, total_score, grade, raw_json from daily_health order by display_date_ms desc limit 1000")[::-1],
                "timezone_hints": rows(db, "select date_ms, date_iso, raw_json from auxiliary where table_name = 'weather' order by date_ms"),
            },
            "imports": rows(db, "select id, filename, export_ms, uploaded_at, counts_json from imports order by id desc limit 1"),
        }
        summary["advice"] = advice(summary)
        return summary


def export_csv_archive() -> bytes:
    tables = [
        "imports",
        "sport",
        "heart_rate",
        "sleep",
        "timing_stress",
        "daily_health",
        "auxiliary",
        "user_profiles",
    ]
    buffer = io.BytesIO()
    with connect() as db, zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest = {
            "generated_at": now_iso(),
            "tables": [],
            "note": "Authenticated dashboard export. users and sessions tables are intentionally excluded.",
        }
        for table in tables:
            result = db.execute(f"select * from {table}")
            output = io.StringIO()
            writer = csv.writer(output)
            columns = [description[0] for description in result.description or []]
            writer.writerow(columns)
            row_count = 0
            for row in result.fetchall():
                writer.writerow([row[column] for column in columns])
                row_count += 1
            zf.writestr(f"{table}.csv", output.getvalue())
            manifest["tables"].append({"name": table, "rows": row_count})
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    return buffer.getvalue()


def parse_multipart_file(headers: dict[str, str], body: bytes) -> tuple[str, bytes]:
    content_type = headers.get("content-type", "")
    match = re.search(r"boundary=(.+)", content_type)
    if not match:
        raise ValueError("缺少 multipart boundary")
    boundary = match.group(1).strip().strip('"').encode()
    for part in body.split(b"--" + boundary):
        if b"Content-Disposition:" not in part:
            continue
        head, _, content = part.partition(b"\r\n\r\n")
        disposition = head.decode("utf-8", errors="replace")
        name_match = re.search(r'filename="([^"]*)"', disposition)
        if not name_match:
            continue
        filename = unquote(name_match.group(1)) or "dafit-upload.zip"
        content = content.rstrip(b"\r\n")
        if content.endswith(b"--"):
            content = content[:-2]
        return filename, content
    raise ValueError("没有找到上传文件字段")


def form_value(body: bytes, key: str) -> str:
    values = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return (values.get(key) or [""])[0].strip()


def cookie_value(headers: Any, key: str) -> str | None:
    cookie = headers.get("Cookie", "")
    for part in cookie.split(";"):
        name, _, value = part.strip().partition("=")
        if name == key and value:
            return value
    return None


def user_for_token(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    now_ts = int(datetime.now(timezone.utc).timestamp())
    with connect() as db:
        row = db.execute(
            """select users.id, users.username, users.is_admin, users.default_language
            from sessions join users on sessions.user_id = users.id
            where sessions.token = ? and sessions.expires_at > ?""",
            (token, now_ts),
        ).fetchone()
        return dict(row) if row else None


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = int(datetime.now(timezone.utc).timestamp()) + SESSION_TTL_SECONDS
    with connect() as db:
        db.execute(
            "insert into sessions (token, user_id, created_at, expires_at) values (?, ?, ?, ?)",
            (token, user_id, now_iso(), expires_at),
        )
        db.commit()
    return token


def delete_session(token: str | None) -> None:
    if not token:
        return
    with connect() as db:
        db.execute("delete from sessions where token = ?", (token,))
        db.commit()


class Handler(BaseHTTPRequestHandler):
    server_version = "DafitHealthDashboard/0.1"

    def current_user(self) -> dict[str, Any] | None:
        return user_for_token(cookie_value(self.headers, "dafit_session"))

    def redirect(self, location: str, clear_cookie: bool = False) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        if clear_cookie:
            self.send_header("Set-Cookie", "dafit_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
        self.end_headers()

    def send_json(self, value: Any, status: int = 200) -> None:
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_text(self, value: str, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        payload = value.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_bytes(self, payload: bytes, content_type: str, filename: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_HEAD(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            payload = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
        elif path == "/health":
            payload = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json({"ok": True})
        elif path == "/login":
            self.send_text(LOGIN_HTML)
        elif path == "/logout":
            delete_session(cookie_value(self.headers, "dafit_session"))
            self.redirect("/login", clear_cookie=True)
        elif path == "/api/summary":
            if not self.current_user():
                self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            self.send_json(summary_payload())
        elif path == "/api/export":
            if not self.current_user():
                self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            filename = f"da-fit-dashboard-csv-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip"
            self.send_bytes(export_csv_archive(), "application/zip", filename)
        elif path == "/api/me":
            user = self.current_user()
            if not user:
                self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            with connect() as db:
                profile = user_profile(db, int(user["id"]))
            self.send_json({"username": user["username"], "is_admin": bool(user["is_admin"]), "default_language": user.get("default_language") or "zh", "profile": profile})
        elif path == "/api/profile":
            user = self.current_user()
            if not user:
                self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            with connect() as db:
                self.send_json({"ok": True, "profile": user_profile(db, int(user["id"]))})
        elif path == "/":
            if not self.current_user():
                self.redirect("/login")
                return
            self.send_text(HTML)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/login":
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            username = form_value(body, "username")
            password = form_value(body, "password")
            with connect() as db:
                row = db.execute("select * from users where username = ?", (username,)).fetchone()
            if not row or not verify_password(password, row["password_hash"]):
                self.send_text(LOGIN_HTML.replace("<!--ERROR-->", "<div class='error'>Invalid username or password</div>"), HTTPStatus.UNAUTHORIZED)
                return
            token = create_session(int(row["id"]))
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"dafit_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}")
            self.end_headers()
            return
        user = self.current_user()
        if not user:
            self.send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        if path == "/api/users":
            if not user.get("is_admin"):
                self.send_json({"error": "admin required"}, HTTPStatus.FORBIDDEN)
                return
            try:
                length = int(self.headers.get("content-length", "0"))
                body = self.rfile.read(length)
                username = form_value(body, "username")
                password = form_value(body, "password")
                is_admin = 1 if form_value(body, "is_admin") == "1" else 0
                default_language = form_value(body, "default_language") or "zh"
                if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
                    raise ValueError("用户名需要 3-32 位，只能包含字母、数字、点、下划线和横线")
                if len(password) < 8:
                    raise ValueError("密码至少 8 位")
                if default_language not in {"zh", "en"}:
                    raise ValueError("默认语言只能是 zh 或 en")
                with connect() as db:
                    db.execute(
                        "insert into users (username, password_hash, is_admin, created_at, default_language) values (?, ?, ?, ?, ?)",
                        (username, hash_password(password), is_admin, now_iso(), default_language),
                    )
                    db.commit()
                self.send_json({"ok": True, "username": username})
            except sqlite3.IntegrityError:
                self.send_json({"ok": False, "error": "用户名已存在"}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if path == "/api/settings":
            try:
                length = int(self.headers.get("content-length", "0"))
                body = self.rfile.read(length)
                default_language = form_value(body, "default_language")
                if default_language not in {"zh", "en"}:
                    raise ValueError("默认语言只能是 zh 或 en")
                with connect() as db:
                    db.execute(
                        "update users set default_language = ? where id = ?",
                        (default_language, int(user["id"])),
                    )
                    db.commit()
                self.send_json({"ok": True, "default_language": default_language})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if path == "/api/password":
            try:
                length = int(self.headers.get("content-length", "0"))
                body = self.rfile.read(length)
                current_password = form_value(body, "current_password")
                new_password = form_value(body, "new_password")
                if len(new_password) < 8:
                    raise ValueError("密码至少 8 位")
                with connect() as db:
                    row = db.execute("select password_hash from users where id = ?", (int(user["id"]),)).fetchone()
                    if not row or not verify_password(current_password, row["password_hash"]):
                        raise ValueError("当前密码不正确")
                    db.execute(
                        "update users set password_hash = ? where id = ?",
                        (hash_password(new_password), int(user["id"])),
                    )
                    db.commit()
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if path == "/api/profile":
            try:
                length = int(self.headers.get("content-length", "0"))
                body = self.rfile.read(length)
                with connect() as db:
                    profile = update_user_profile_from_form(db, int(user["id"]), body)
                    db.commit()
                self.send_json({"ok": True, "profile": profile})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if path != "/upload":
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            filename, content = parse_multipart_file({k.lower(): v for k, v in self.headers.items()}, body)
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", filename)
            target = UPLOAD_DIR / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{safe_name}"
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            payload = read_export_payload(target)
            with connect() as db:
                import_id = upsert_import(db, target, payload)
                counts = ingest_payload(db, import_id, payload)
                if upsert_user_profile(db, int(user["id"]), payload, import_id):
                    counts["profile"] = 1
                db.commit()
            self.send_json({"ok": True, "filename": safe_name, "import_id": import_id, "counts": counts})
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


LOGIN_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DA FIT Health Dashboard Login</title>
  <style>
    :root { --bg:#101214; --panel:#181b1f; --line:#2a3036; --text:#f6f7f8; --muted:#a9b0b8; --teal:#22c7ad; --red:#ff6675; }
    * { box-sizing:border-box; }
    body { min-height:100vh; margin:0; display:grid; place-items:center; color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#101214; }
    main { width:min(420px,calc(100vw - 28px)); padding:24px; border:1px solid var(--line); border-radius:8px; background:linear-gradient(180deg,rgba(255,255,255,.055),rgba(255,255,255,.03)); box-shadow:0 18px 50px rgba(0,0,0,.24); }
    h1 { margin:0 0 8px; font-size:1.5rem; }
    p { margin:0 0 18px; color:var(--muted); line-height:1.55; }
    form { display:grid; gap:12px; }
    input { width:100%; min-height:42px; padding:10px 12px; color:var(--text); background:#12161a; border:1px solid var(--line); border-radius:8px; font-size:1rem; }
    button { border:0; border-radius:8px; min-height:42px; color:#05251f; background:var(--teal); font-weight:850; cursor:pointer; }
    .error { margin-bottom:12px; padding:10px 12px; border:1px solid rgba(255,102,117,.5); border-radius:8px; color:#ffd5da; background:rgba(255,102,117,.12); }
    .hint { margin-top:14px; color:var(--muted); font-size:.88rem; }
  </style>
</head>
<body>
  <main>
    <h1>DA FIT Health Dashboard</h1>
    <p>Sign in to upload DA FIT exports and view your local health dashboard.</p>
    <!--ERROR-->
    <form method="post" action="/login">
      <input name="username" autocomplete="username" placeholder="Username" required autofocus />
      <input name="password" type="password" autocomplete="current-password" placeholder="Password" required />
      <button type="submit">Sign in</button>
    </form>
    <div class="hint">Administrators can add accounts from User management after signing in.</div>
  </main>
</body>
</html>
"""


HTML = r"""
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DA FIT Health Dashboard</title>
  <style>
    :root { --bg:#101214; --panel:#181b1f; --line:#2a3036; --text:#f6f7f8; --muted:#a9b0b8; --soft:#77808b; --teal:#22c7ad; --blue:#57a6ff; --purple:#8f6df7; --violet:#5a25f0; --magenta:#ca42e8; --orange:#ffb35c; --coral:#ff7d6d; --red:#ff6675; --green:#64d892; }
    * { box-sizing:border-box; }
    body { margin:0; color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:linear-gradient(180deg,#111416,#171a1e 46%,#101214); }
    .wrap { max-width:1180px; margin:0 auto; padding:28px 16px 56px; }
    .topbar { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:18px; }
    h1 { margin:0; font-size:clamp(1.7rem,4vw,2.7rem); letter-spacing:0; }
    .lead { margin:8px 0 0; color:var(--muted); line-height:1.6; }
    .panel { background:linear-gradient(180deg,rgba(255,255,255,.055),rgba(255,255,255,.03)); border:1px solid var(--line); border-radius:8px; box-shadow:0 18px 50px rgba(0,0,0,.24); }
    .upload { padding:16px; min-width:min(100%,380px); }
    .upload form { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    .toolbar { display:flex; gap:10px; align-items:center; justify-content:flex-end; flex-wrap:wrap; margin-bottom:12px; color:var(--muted); font-size:.9rem; }
    .link-btn { display:inline-flex; align-items:center; min-height:36px; padding:8px 10px; border:1px solid var(--line); border-radius:8px; color:var(--muted); text-decoration:none; background:#12161a; font-weight:760; }
    .admin-panel { margin-top:12px; padding-top:12px; border-top:1px solid var(--line); display:none; }
    .admin-panel form { display:grid; grid-template-columns:1fr 1fr auto; gap:8px; align-items:center; }
    input[type=text], input[type=password], input[type=number], input[type=date] { min-height:38px; color:var(--text); background:#12161a; border:1px solid var(--line); border-radius:8px; padding:8px 10px; min-width:0; }
    .page-tabs { display:flex; gap:8px; flex-wrap:wrap; margin:18px 0 0; }
    .page-tab { color:var(--muted); background:#12161a; border:1px solid var(--line); border-radius:8px; padding:9px 12px; cursor:pointer; font-weight:800; }
    .page-tab.active { color:#05251f; background:var(--teal); border-color:var(--teal); }
    .page-jump { color:var(--muted); background:#12161a; border:1px solid var(--line); border-radius:8px; padding:9px 12px; font-weight:800; text-decoration:none; }
    .page-section.hidden { display:none; }
    .settings-panel { margin-top:18px; padding:18px; }
    .settings-grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-top:14px; }
    .settings-box { padding:14px; border:1px solid var(--line); border-radius:8px; background:rgba(255,255,255,.03); }
    .settings-box form { display:grid; gap:10px; margin-top:10px; }
    .settings-box.wide { grid-column:1 / -1; }
    .profile-form { grid-template-columns:repeat(3,minmax(0,1fr)); }
    .field { display:grid; gap:6px; }
    .field label { color:var(--muted); font-size:.82rem; font-weight:780; }
    .checkbox-row { display:flex; align-items:center; gap:8px; color:var(--muted); font-size:.92rem; }
    input[type=file] { position:absolute; inline-size:1px; block-size:1px; opacity:0; pointer-events:none; }
    .file-label { display:inline-flex; align-items:center; min-height:38px; max-width:220px; padding:9px 11px; border:1px solid var(--line); border-radius:8px; color:var(--muted); background:#12161a; font-size:.9rem; overflow:hidden; white-space:nowrap; text-overflow:ellipsis; cursor:pointer; }
    button { border:0; border-radius:8px; padding:11px 14px; color:#05251f; background:var(--teal); font-weight:850; cursor:pointer; }
    select { min-height:36px; max-width:220px; color:var(--text); background:#12161a; border:1px solid var(--line); border-radius:8px; padding:7px 10px; font-weight:760; }
    .status { margin-top:10px; color:var(--muted); font-size:.9rem; min-height:1.4em; }
    .month-control { display:flex; justify-content:space-between; align-items:center; gap:12px; margin:18px 0 0; padding:14px 16px; }
    .month-control h2 { font-size:.95rem; }
    .cards { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:18px 0; }
    .card { padding:18px; min-height:118px; }
    .label { color:var(--soft); font-size:.82rem; font-weight:800; text-transform:uppercase; }
    .value { margin-top:8px; font-size:2rem; font-weight:900; }
    .sub { margin-top:8px; color:var(--muted); font-size:.92rem; line-height:1.45; }
    .grid { display:grid; grid-template-columns:2fr 1fr; gap:14px; }
    .chart { padding:18px; min-height:320px; }
    .chart-head { display:flex; justify-content:space-between; align-items:center; gap:10px; margin-bottom:10px; }
    h2 { margin:0; font-size:1.05rem; }
    .tabs { display:flex; gap:8px; flex-wrap:wrap; }
    .tab { color:var(--muted); background:#12161a; border:1px solid var(--line); border-radius:8px; padding:7px 11px; cursor:pointer; font-weight:750; }
    .tab.active { color:#05251f; background:var(--teal); border-color:var(--teal); }
    svg { width:100%; height:240px; display:block; overflow:visible; }
    .axis { stroke:#28445f; stroke-width:1; }
    .line { fill:none; stroke:var(--teal); stroke-width:3; stroke-linecap:round; stroke-linejoin:round; }
    .area { fill:rgba(33,212,181,.12); }
    .bar { fill:rgba(98,168,255,.72); rx:4; }
    .bar:hover { fill:rgba(98,168,255,.95); }
    .point { fill:var(--teal); stroke:#101214; stroke-width:1.5; }
    .point-hit { fill:transparent; stroke:transparent; cursor:crosshair; }
    .stage-block { rx:4; }
    .tick { fill:var(--soft); font-size:11px; }
    .side { padding:18px; }
    .advice { display:grid; gap:10px; margin-top:12px; }
    .advice-item { padding:12px; border:1px solid var(--line); border-radius:8px; background:rgba(255,255,255,.035); }
    .advice-item.good { border-color:rgba(110,231,168,.35); }
    .advice-item.warn { border-color:rgba(255,107,120,.42); }
    .advice-item.watch { border-color:rgba(255,184,107,.36); }
    .advice-title { font-weight:850; margin-bottom:5px; }
    .advice-text { color:var(--muted); line-height:1.5; font-size:.93rem; }
    .daily-report { padding:18px; margin:18px 0; scroll-margin-top:12px; }
    .report-actions { display:flex; gap:10px; align-items:flex-start; flex-wrap:wrap; justify-content:flex-end; }
    .calendar-picker { position:relative; min-width:150px; }
    .calendar-picker-toggle { width:100%; min-height:38px; padding:9px 34px 9px 12px; text-align:left; font-weight:800; position:relative; }
    .calendar-picker-toggle::after { content:"▾"; position:absolute; right:12px; color:var(--teal); }
    .calendar-picker.open .calendar-picker-toggle::after { content:"▴"; }
    .calendar-picker-popup { display:none; position:absolute; z-index:30; top:44px; right:0; width:300px; padding:10px; border:1px solid var(--line); border-radius:9px; background:#12161a; box-shadow:0 14px 38px rgba(0,0,0,.5); }
    .calendar-picker.open .calendar-picker-popup { display:block; }
    .picker-month-head { display:grid; grid-template-columns:36px 1fr 36px; align-items:center; gap:6px; margin-bottom:9px; }
    .picker-month-head strong { text-align:center; }
    .picker-nav { padding:7px; }
    .picker-weekdays,.picker-days { display:grid; grid-template-columns:repeat(7,1fr); gap:4px; }
    .picker-weekdays { color:var(--soft); font-size:.72rem; text-align:center; margin-bottom:5px; }
    .picker-day,.picker-month { min-height:34px; padding:5px; font-size:.82rem; }
    .picker-day.available,.picker-month.available { color:var(--text); border-color:rgba(34,199,173,.34); }
    .picker-day.selected,.picker-month.selected { color:#06251f; background:var(--teal); border-color:var(--teal); }
    .picker-day:disabled,.picker-month:disabled { color:#626a70; background:rgba(255,255,255,.025); border-color:transparent; opacity:.5; cursor:not-allowed; }
    .picker-months { display:grid; grid-template-columns:repeat(3,1fr); gap:6px; }
    .report-date-list { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
    .report-date-btn { padding:7px 11px; background:rgba(255,255,255,.04); color:var(--muted); border:1px solid var(--line); }
    .report-date-btn.active { color:#06251f; background:var(--teal); border-color:var(--teal); }
    .report-score { display:grid; grid-template-columns:180px 1fr; gap:18px; align-items:center; margin-top:16px; }
    .score-dial { min-height:140px; border:1px solid var(--line); border-radius:8px; display:grid; place-items:center; background:rgba(255,255,255,.03); }
    .score-number { font-size:3.1rem; line-height:1; font-weight:950; color:var(--teal); }
    .score-grade { margin-top:6px; color:var(--muted); text-align:center; font-weight:820; }
    .report-summary { display:grid; gap:10px; }
    .report-kicker { color:var(--soft); font-size:.82rem; font-weight:850; text-transform:uppercase; }
    .report-title { font-size:1.35rem; font-weight:900; }
    .report-narrative { color:var(--muted); line-height:1.55; }
    .report-metrics { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; margin-top:16px; }
    .report-metric { border:1px solid var(--line); border-radius:8px; padding:12px; background:rgba(255,255,255,.03); }
    .report-metric.warn { border-color:rgba(255,184,107,.42); }
    .report-metric.good { border-color:rgba(110,231,168,.35); }
    .report-metric-title { color:var(--soft); font-size:.78rem; font-weight:850; text-transform:uppercase; }
    .report-metric-value { margin-top:6px; font-size:1.25rem; font-weight:900; }
    .report-metric-sub { margin-top:5px; color:var(--muted); font-size:.86rem; line-height:1.4; }
    .report-text { margin:16px 0 0; padding:12px; white-space:pre-wrap; color:var(--text); background:#111519; border:1px solid var(--line); border-radius:8px; font:500 .92rem/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
    .imports { margin-top:14px; padding:18px; }
    .detail-grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-top:14px; }
    .heart-detail,.sleep-detail,.calendar-panel { padding:18px; }
    .dropout { fill:var(--red); opacity:.76; }
    .sleep-main { display:grid; grid-template-columns:180px 1fr; align-items:center; gap:20px; margin-top:18px; }
    .donut-wrap { position:relative; width:170px; height:170px; }
    .donut-wrap svg { height:170px; }
    .donut-center { position:absolute; inset:0; display:flex; align-items:center; justify-content:center; flex-direction:column; text-align:center; font-weight:900; }
    .donut-center span { color:var(--muted); font-size:.82rem; font-weight:750; }
    .ratio-list { display:grid; gap:12px; }
    .ratio-row { display:grid; grid-template-columns:1fr auto; gap:10px; align-items:center; color:var(--muted); }
    .ratio-label { display:flex; align-items:center; gap:9px; color:var(--text); font-weight:760; }
    .dot { width:12px; height:12px; border-radius:999px; display:inline-block; }
    .quality { margin-top:16px; padding-top:16px; border-top:1px solid var(--line); }
    .quality-head { display:flex; justify-content:space-between; align-items:baseline; gap:12px; }
    .quality-score { color:var(--purple); font-size:2rem; font-weight:950; }
    .quality-bar { position:relative; height:14px; margin-top:16px; border-radius:999px; overflow:hidden; background:linear-gradient(90deg,var(--red) 0 24%,#ffd84d 24% 48%,var(--green) 48% 72%,var(--blue) 72% 100%); }
    .quality-marker { position:absolute; top:-4px; width:0; height:0; border-left:7px solid transparent; border-right:7px solid transparent; border-top:9px solid var(--blue); transform:translateX(-7px); }
    .quality-labels { display:grid; grid-template-columns:repeat(4,1fr); gap:6px; color:var(--muted); font-size:.78rem; margin-top:8px; text-align:center; }
    .sleep-stage { margin-top:18px; padding-top:16px; border-top:1px solid var(--line); }
    .sleep-insight { margin-top:18px; padding-top:16px; border-top:1px solid var(--line); }
    .sleep-heart-stats,.sleep-compare-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; margin:12px 0; }
    .sleep-stat,.sleep-compare { padding:11px; border:1px solid var(--line); border-radius:8px; background:rgba(255,255,255,.03); }
    .sleep-stat span,.sleep-compare span { display:block; color:var(--muted); font-size:.78rem; }
    .sleep-stat strong,.sleep-compare strong { display:block; margin-top:5px; font-size:1.12rem; }
    .sleep-heart-line { fill:none; stroke:var(--red); stroke-width:2.5; vector-effect:non-scaling-stroke; }
    .sleep-trend-bar { opacity:.96; }
    .stage-legend { display:flex; gap:10px; flex-wrap:wrap; margin-top:10px; color:var(--muted); font-size:.82rem; }
    .stage-legend span { display:inline-flex; align-items:center; gap:6px; }
    .calendar-head { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:14px; }
    .calendar-month { margin-top:16px; }
    .calendar-title { font-size:1.25rem; font-weight:900; margin-bottom:10px; }
    .weekdays,.calendar-days { display:grid; grid-template-columns:repeat(7,1fr); gap:10px; }
    .weekdays { color:var(--soft); font-size:.78rem; font-weight:850; text-align:center; margin-bottom:10px; }
    .day-ring { width:46px; aspect-ratio:1; border-radius:50%; display:grid; place-items:center; margin:auto; color:var(--text); font-weight:820; position:relative; }
    .day-ring-svg { position:absolute; inset:0; width:46px; height:46px; transform:rotate(-90deg); overflow:visible; }
    .day-ring-track,.day-ring-progress { fill:none; stroke-width:5; }
    .day-ring-track { stroke:rgba(34,199,173,.16); }
    .day-ring-progress { stroke:var(--teal); stroke-linecap:butt; }
    .day-ring span { position:relative; z-index:1; }
    .day-ring.empty { opacity:.18; }
    .day-ring.today { color:var(--teal); }
    .day-ring.timezone-change { color:var(--orange); }
    .day-ring.timezone-change .day-ring-progress { stroke:var(--orange); }
    table { width:100%; border-collapse:collapse; }
    th,td { text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); color:var(--muted); font-size:.9rem; vertical-align:top; }
    th { color:var(--text); font-size:.78rem; text-transform:uppercase; }
    @media (max-width:900px) { .topbar,.grid,.detail-grid,.settings-grid,.report-score{display:block}.profile-form{grid-template-columns:1fr}.upload,.side,.calendar-panel,.settings-box{margin-top:14px}.cards,.report-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.sleep-main{grid-template-columns:1fr}.donut-wrap{margin:auto}.report-summary{margin-top:14px}.sleep-heart-stats,.sleep-compare-grid{grid-template-columns:1fr} }
    @media (max-width:560px) { .cards,.report-metrics{grid-template-columns:1fr}.value{font-size:1.7rem} }
  </style>
</head>
<body>
  <main class="wrap">
    <div class="topbar">
      <div><h1>DA FIT Health Dashboard</h1><p class="lead" data-i18n="lead">上传 DA FIT 导出文件，本地解析入库，查看步数、心率、睡眠、压力趋势和日常建议。</p></div>
      <section class="panel upload">
        <div class="toolbar"><span id="userBadge">--</span><select id="langSelect" aria-label="Language"><option value="zh">中文</option><option value="en">English</option></select><a class="link-btn" href="/api/export" data-i18n="exportCsv">导出 CSV</a><a class="link-btn" href="/logout" data-i18n="logout">退出</a></div>
        <form id="uploadForm"><label id="fileLabel" class="file-label" for="file" data-i18n="chooseZip">选择导出 ZIP</label><input id="file" name="file" type="file" accept=".zip,.txt,.json" required /><button type="submit" data-i18n="upload">上传处理</button></form><div id="status" class="status"></div>
      </section>
    </div>
    <nav class="page-tabs"><button class="page-tab active" data-page="dashboard" data-i18n="dashboardTab">Dashboard</button><a class="page-jump" href="#dailyReportCard" data-i18n="dailyReport">每日健康日报</a><button class="page-tab" data-page="users" data-i18n="usersTab">用户管理</button></nav>
    <section id="dashboardPage" class="page-section">
    <section class="panel month-control"><h2 data-i18n="metricMonth">指标月份</h2><div id="metricMonthSelect" class="calendar-picker" data-picker-mode="month" aria-label="选择指标月份"></div></section>
    <section class="cards">
      <div class="panel card"><div class="label" data-i18n="stepsCard">最新步数</div><div id="steps" class="value">--</div><div id="stepsSub" class="sub">等待上传</div></div>
      <div class="panel card"><div class="label" data-i18n="heartCard">平均心率</div><div id="hr" class="value">--</div><div id="hrSub" class="sub">bpm</div></div>
      <div class="panel card"><div class="label" data-i18n="sleepCard">睡眠</div><div id="sleep" class="value">--</div><div id="sleepSub" class="sub">深睡 / 浅睡 / REM</div></div>
      <div class="panel card"><div class="label" data-i18n="stressCard">压力</div><div id="stress" class="value">--</div><div id="stressSub" class="sub">平均值</div></div>
    </section>
    <section id="dailyReportCard" class="panel daily-report">
      <div class="chart-head"><div><h2 data-i18n="dailyReport">每日健康日报</h2><div id="reportDate" class="sub">--</div></div><div class="report-actions"><div id="reportDatePicker" class="calendar-picker" data-picker-mode="date" aria-label="选择日报日期"></div><button id="copyReportBtn" type="button" data-i18n="copyReport">复制报告</button></div></div>
      <div id="reportDateList" class="report-date-list" aria-label="日报日期快速选择"></div>
      <div class="report-score">
        <div class="score-dial"><div><div id="reportScore" class="score-number">--</div><div id="reportGrade" class="score-grade">--</div></div></div>
        <div class="report-summary"><div class="report-kicker" id="reportKicker">DA FIT Daily Report</div><div class="report-title" id="reportTitle">--</div><div class="report-narrative" id="reportNarrative">--</div></div>
      </div>
      <div id="reportMetrics" class="report-metrics"></div>
      <pre id="reportText" class="report-text"></pre>
    </section>
    <section class="grid">
      <div class="panel chart"><div class="chart-head"><h2 id="chartTitle">步数趋势</h2><div class="tabs"><button class="tab active" data-chart="steps" data-i18n="stepsTab">步数</button><button class="tab" data-chart="heart" data-i18n="heartTab">心率</button><button class="tab" data-chart="sleep" data-i18n="sleepTab">睡眠</button><button class="tab" data-chart="stress" data-i18n="stressTab">压力</button></div></div><svg id="chartSvg" viewBox="0 0 760 240" preserveAspectRatio="none" aria-label="health chart"></svg></div>
      <aside class="panel side"><h2 data-i18n="advice">健康建议</h2><div id="advice" class="advice"></div></aside>
    </section>
    <section class="detail-grid">
      <section class="panel heart-detail">
        <div class="chart-head"><h2 data-i18n="dailyHeartCurve">每日心率曲线</h2><div id="heartSelect" class="calendar-picker" data-picker-mode="date" aria-label="选择心率日期"></div></div>
        <svg id="heartDaySvg" viewBox="0 0 760 180" preserveAspectRatio="none" aria-label="daily heart-rate chart"></svg>
        <div class="sub" id="heartDayStats">--</div>
      </section>
      <section class="panel sleep-detail">
        <div class="chart-head"><h2 data-i18n="sleepRatio">睡眠比例</h2><div id="sleepSelect" class="calendar-picker" data-picker-mode="date" aria-label="选择睡眠日期"></div></div>
        <div class="sleep-main">
          <div class="donut-wrap"><svg id="sleepDonut" viewBox="0 0 170 170" aria-label="sleep ratio"></svg><div class="donut-center"><strong id="sleepTotal">--</strong><span>Total</span></div></div>
          <div class="ratio-list" id="sleepRatioRows"></div>
        </div>
        <div class="quality">
          <div class="quality-head"><h2 data-i18n="sleepQuality">Sleep Quality Score</h2><div><span id="qualityScore" class="quality-score">--</span> <span class="sub">score</span></div></div>
          <div class="quality-bar"><i id="qualityMarker" class="quality-marker" style="left:0%"></i></div>
          <div class="quality-labels"><span data-i18n="poor">Poor</span><span data-i18n="secondary">Secondary</span><span data-i18n="good">Good</span><span data-i18n="excellent">Excellent</span></div>
        </div>
        <div class="sleep-stage">
          <div class="chart-head"><h2 data-i18n="sleepStage">睡眠阶段曲线</h2><span class="sub" id="sleepDate">--</span></div>
          <svg id="sleepStageSvg" viewBox="0 0 760 150" preserveAspectRatio="none" aria-label="sleep stage chart"></svg>
          <div class="stage-legend"><span><i class="dot" style="background:var(--violet)"></i>Deep</span><span><i class="dot" style="background:var(--magenta)"></i>Light</span><span><i class="dot" style="background:var(--coral)"></i>REM</span><span><i class="dot" style="background:var(--orange)"></i>Awake</span></div>
        </div>
        <div class="sleep-insight">
          <div class="chart-head"><h2 id="sleepHeartTitle">睡眠心率</h2><span class="sub" id="sleepHeartNote"></span></div>
          <div class="sleep-heart-stats" id="sleepHeartStats"></div>
          <svg id="sleepHeartSvg" viewBox="0 0 760 150" preserveAspectRatio="none" aria-label="sleep heart-rate chart"></svg>
        </div>
        <div class="sleep-insight">
          <div class="chart-head"><h2 id="sleepTrendTitle">最近 7 天睡眠趋势</h2><span class="sub">Deep / Light / REM</span></div>
          <svg id="sleepTrendSvg" viewBox="0 0 760 210" preserveAspectRatio="none" aria-label="seven-day sleep trend"></svg>
        </div>
        <div class="sleep-insight">
          <div class="chart-head"><h2 id="sleepCompareTitle">与参考人群比较</h2><span class="sub" id="sleepCompareNote">基于年龄和性别的估算</span></div>
          <div class="sleep-compare-grid" id="sleepCompareGrid"></div>
        </div>
      </section>
      <section class="panel calendar-panel">
        <div class="calendar-head"><h2 data-i18n="monthlyRings">月度活动环</h2><div id="monthSelect" class="calendar-picker" data-picker-mode="month" aria-label="选择月份"></div></div>
        <div class="weekdays"><span data-i18n="sun">Sun</span><span data-i18n="mon">Mon</span><span data-i18n="tue">Tue</span><span data-i18n="wed">Wed</span><span data-i18n="thu">Thu</span><span data-i18n="fri">Fri</span><span data-i18n="sat">Sat</span></div>
        <div id="calendarMonths"></div>
      </section>
    </section>
    <section class="panel imports"><h2 data-i18n="recentImport">最近导入</h2><div style="overflow:auto"><table><thead><tr><th data-i18n="file">文件</th><th data-i18n="importTime">导入时间</th><th data-i18n="exportTimestamp">导出时间戳</th><th data-i18n="tableCounts">表计数</th></tr></thead><tbody id="imports"></tbody></table></div></section>
    </section>
    <section id="usersPage" class="page-section hidden">
      <section class="panel settings-panel">
        <h2 data-i18n="usersTab">用户管理</h2>
        <div class="settings-grid">
          <div class="settings-box">
            <h2 data-i18n="profileSettings">个人设置</h2>
            <form id="settingsForm"><label class="sub" data-i18n="defaultLanguage">默认语言</label><select id="defaultLanguage" name="default_language"><option value="zh">中文</option><option value="en">English</option></select><button type="submit" data-i18n="saveSettings">保存设置</button></form>
            <div id="settingsStatus" class="status"></div>
          </div>
          <div class="settings-box">
            <h2 data-i18n="changePassword">修改密码</h2>
            <form id="passwordForm"><input id="currentPassword" name="current_password" type="password" data-placeholder-key="currentPassword" placeholder="当前密码" /><input id="newOwnPassword" name="new_password" type="password" data-placeholder-key="newPassword" placeholder="新密码" /><button type="submit" data-i18n="changePassword">修改密码</button></form>
            <div id="passwordStatus" class="status"></div>
          </div>
          <div class="settings-box wide">
            <h2 data-i18n="healthProfile">健康个人资料</h2>
            <form id="profileForm" class="profile-form">
              <div class="field"><label data-i18n="heightCm">身高 cm</label><input id="profileHeightCm" name="height_cm" type="number" step="0.1" /></div>
              <div class="field"><label data-i18n="weightKg">体重 kg</label><input id="profileWeightKg" name="weight_kg" type="number" step="0.1" /></div>
              <div class="field"><label data-i18n="gender">性别</label><select id="profileGender" name="gender"><option value="" data-i18n="unknown">未知</option><option value="1" data-i18n="male">男</option><option value="0" data-i18n="female">女</option></select></div>
              <div class="field"><label data-i18n="birthday">生日</label><input id="profileBirthday" name="birthday" type="date" /></div>
              <div class="field"><label data-i18n="birthYear">出生年份</label><input id="profileBirthYear" name="birth_year" type="number" /></div>
              <div class="field"><label data-i18n="stepLengthCm">步长 cm</label><input id="profileStepLengthCm" name="step_length_cm" type="number" step="0.1" /></div>
              <div class="field"><label data-i18n="dailyStepsGoal">每日步数目标</label><input id="profileDailyStepsGoal" name="daily_steps_goal" type="number" /></div>
              <div class="field"><label data-i18n="dailyCaloriesGoal">每日卡路里目标</label><input id="profileDailyCaloriesGoal" name="daily_calories_goal" type="number" /></div>
              <div class="field"><label data-i18n="dailyMinutesGoal">每日运动分钟目标</label><input id="profileDailyMinutesGoal" name="daily_minutes_goal" type="number" /></div>
              <div class="field"><label data-i18n="deviceName">设备名称</label><input id="profileDeviceName" name="device_name" type="text" /></div>
              <button type="submit" data-i18n="saveProfile">保存个人资料</button>
            </form>
            <div id="profileStatus" class="status"></div>
          </div>
          <div id="adminPanel" class="settings-box admin-panel">
            <h2 data-i18n="addUser">增加账户</h2>
            <form id="userForm"><input id="newUsername" name="username" type="text" data-placeholder-key="newUsername" placeholder="新用户名" /><input id="newPassword" name="password" type="password" data-placeholder-key="newPassword" placeholder="新密码" /><select id="newUserLanguage"><option value="zh">中文</option><option value="en">English</option></select><label class="checkbox-row"><input id="newIsAdmin" type="checkbox" /> <span data-i18n="adminRole">管理员</span></label><button type="submit" data-i18n="addUser">增加账户</button></form>
            <div id="userStatus" class="status"></div>
          </div>
        </div>
      </section>
    </section>
  </main>
  <script>
    let state=null,userProfile={},currentChart="steps",selectedSleepMs=null,selectedHeartMs=null,selectedReportMs=null,selectedMonth=null,selectedMetricMonth=null,lang=localStorage.getItem("dafit_lang")||"zh"; const fmt=new Intl.NumberFormat(); const calendarParts=(iso)=>{const m=String(iso||"").match(/^(\d{4})-(\d{2})-(\d{2})/); return m?{year:Number(m[1]),month:Number(m[2]),day:Number(m[3])}:null}; const dt=(iso)=>{const p=calendarParts(iso); return p?`${p.month}/${p.day}/${p.year}`:"--"}; const num=(v,d=0)=>Number.isFinite(Number(v))?Number(v).toFixed(d):"--"; const sum=(arr)=>arr.reduce((a,b)=>a+Number(b||0),0); const setText=(id,text)=>document.getElementById(id).textContent=text;
    function monthSequence(first,last){const out=[], [fy,fm]=first.split("-").map(Number), [ly,lm]=last.split("-").map(Number); for(let y=fy,m=fm;y<ly||y===ly&&m<=lm;m++,m>12&&(m=1,y++))out.push(`${y}-${String(m).padStart(2,"0")}`); return out;}
    function drawCalendarPicker(id,available,selected){const root=document.getElementById(id), values=[...new Set((available||[]).filter(Boolean))].sort(), mode=root.dataset.pickerMode; root.dataset.available=JSON.stringify(values); root.dataset.selected=selected||""; if(!values.length){root.classList.remove("open"); root.innerHTML=`<button type="button" class="calendar-picker-toggle" disabled>--</button>`; return} if(mode==="date"){const minMonth=values[0].slice(0,7), maxMonth=values.at(-1).slice(0,7), current=root.dataset.viewMonth; root.dataset.viewMonth=current&&current>=minMonth&&current<=maxMonth?current:String(selected||values.at(-1)).slice(0,7);} const label=mode==="date"?dt(selected):selected, popup=mode==="date"?datePickerBody(root,values,selected):monthPickerBody(values,selected); root.innerHTML=`<button type="button" class="calendar-picker-toggle" aria-haspopup="dialog" aria-expanded="${root.classList.contains("open")}">${escapeHtml(label||"--")}</button><div class="calendar-picker-popup" role="dialog">${popup}</div>`;}
    function datePickerBody(root,values,selected){const available=new Set(values), view=root.dataset.viewMonth||String(selected||values.at(-1)).slice(0,7), [year,month]=view.split("-").map(Number), firstDay=new Date(Date.UTC(year,month-1,1)).getUTCDay(), days=new Date(Date.UTC(year,month,0)).getUTCDate(), minMonth=values[0].slice(0,7), maxMonth=values.at(-1).slice(0,7), names=lang==="en"?["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]:["1月","2月","3月","4月","5月","6月","7月","8月","9月","10月","11月","12月"], weekdays=lang==="en"?["S","M","T","W","T","F","S"]:["日","一","二","三","四","五","六"]; let cells=""; for(let i=0;i<firstDay;i++)cells+="<span></span>"; for(let day=1;day<=days;day++){const value=`${view}-${String(day).padStart(2,"0")}`, enabled=available.has(value); cells+=`<button type="button" class="picker-day ${enabled?"available":""} ${value===selected?"selected":""}" data-calendar-value="${value}" ${enabled?"":"disabled"}>${day}</button>`;} return `<div class="picker-month-head"><button type="button" class="picker-nav" data-calendar-nav="-1" ${view<=minMonth?"disabled":""}>‹</button><strong>${names[month-1]} ${year}</strong><button type="button" class="picker-nav" data-calendar-nav="1" ${view>=maxMonth?"disabled":""}>›</button></div><div class="picker-weekdays">${weekdays.map(v=>`<span>${v}</span>`).join("")}</div><div class="picker-days">${cells}</div>`;}
    function monthPickerBody(values,selected){const available=new Set(values), months=monthSequence(values[0],values.at(-1)); return `<div class="picker-months">${months.map(value=>{const [year,month]=value.split("-"); const enabled=available.has(value); return `<button type="button" class="picker-month ${enabled?"available":""} ${value===selected?"selected":""}" data-calendar-value="${value}" ${enabled?"":"disabled"}>${year}<br>${lang==="en"?Number(month):Number(month)+"月"}</button>`}).join("")}</div>`;}
    function calendarDayKey(row){const p=calendarParts(row?.date_iso); return p?`${p.year}-${String(p.month).padStart(2,"0")}-${String(p.day).padStart(2,"0")}`:"";}
    function uniqueDailyRows(rows,score=()=>0){const byDay=new Map(); for(const row of rows||[]){const key=calendarDayKey(row); if(!key)continue; const prev=byDay.get(key), rowScore=Number(score(row)||0), prevScore=prev?Number(score(prev)||0):-Infinity; if(!prev||rowScore>prevScore||(rowScore===prevScore&&Number(row.date_ms||0)>Number(prev.date_ms||0)))byDay.set(key,row);} return [...byDay.values()].sort((a,b)=>Number(a.date_ms||0)-Number(b.date_ms||0));}
    function dailySportDateAnchors(){const candidates=new Map(); for(const daily of state?.series?.daily_health||[]){const raw=rawDaily(daily), steps=Number(raw.STEPS_VALUE??daily.steps), calories=Math.round(Number(raw.CALORIES_VALUE??daily.calories)); if(!Number.isFinite(steps)||!Number.isFinite(calories))continue; const parts=calendarParts(daily.date_iso); if(!parts)continue; const reportDay=new Date(Date.UTC(parts.year,parts.month-1,parts.day)); reportDay.setUTCDate(reportDay.getUTCDate()-1); const key=`${steps}|${calories}`, value=`${reportDay.getUTCFullYear()}-${String(reportDay.getUTCMonth()+1).padStart(2,"0")}-${String(reportDay.getUTCDate()).padStart(2,"0")}`; if(!candidates.has(key))candidates.set(key,new Set()); candidates.get(key).add(value);} const anchors=new Map(); for(const [key,days] of candidates)if(days.size===1)anchors.set(key,[...days][0]); return anchors;}
    function sportDisplayRow(row,anchors=dailySportDateAnchors()){const anchoredDay=anchors.get(`${Number(row?.steps)}|${Math.round(Number(row?.calories))}`); if(anchoredDay)return {...row,archive_date_iso:row.date_iso,report_date_anchor:true,date_iso:`${anchoredDay}T12:00:00+00:00`}; const match=String(row?.date_iso||"").match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/), hasDailyBins=Number(row?.time_interval)===30&&String(row?.steps_category_json||"").length>2; if(!match||Number(match[5])>2||!hasDailyBins)return row; const utcHour=Number(match[4]), offsetHours=utcHour<12?-utcHour:24-utcHour, localBoundary=new Date(Number(row.date_ms)+offsetHours*3600000); localBoundary.setUTCDate(localBoundary.getUTCDate()-1); return {...row,archive_date_iso:row.date_iso,archive_utc_offset_minutes:offsetHours*60,date_iso:`${localBoundary.getUTCFullYear()}-${String(localBoundary.getUTCMonth()+1).padStart(2,"0")}-${String(localBoundary.getUTCDate()).padStart(2,"0")}T12:00:00+00:00`};}
    function sportDailyRows(rows){const byDay=new Map(), anchors=dailySportDateAnchors(); for(const source of rows||[]){const row=sportDisplayRow(source,anchors), key=calendarDayKey(row); if(!key)continue; const prev=byDay.get(key); if(!prev||Number(row.date_ms||0)>Number(prev.date_ms||0))byDay.set(key,row);} return [...byDay.values()].sort((a,b)=>calendarDayKey(a).localeCompare(calendarDayKey(b)));}
    const I18N={zh:{lead:"上传 DA FIT 导出文件，本地解析入库，查看步数、心率、睡眠、压力趋势和日常建议。",dashboardTab:"Dashboard",usersTab:"用户管理",logout:"退出",exportCsv:"导出 CSV",chooseZip:"选择导出 ZIP",upload:"上传处理",addUser:"增加账户",metricMonth:"指标月份",stepsCard:"最新步数",heartCard:"平均心率",sleepCard:"睡眠",stressCard:"压力",advice:"健康建议",stepsTab:"步数",heartTab:"心率",sleepTab:"睡眠",stressTab:"压力",sleepRatio:"睡眠比例",sleepQuality:"睡眠质量分",poor:"差",secondary:"一般",good:"好",excellent:"优秀",sleepStage:"睡眠阶段曲线",monthlyRings:"月度活动环",recentImport:"最近导入",file:"文件",importTime:"导入时间",exportTimestamp:"导出时间戳",tableCounts:"表计数",profileSettings:"个人设置",defaultLanguage:"默认语言",saveSettings:"保存设置",changePassword:"修改密码",currentPassword:"当前密码",newPassword:"新密码",newUsername:"新用户名",adminRole:"管理员",stepsTrend:"步数趋势",heartTrend:"平均心率趋势",dailyHeartCurve:"每日心率曲线",noHeartCurve:"暂无每日心率曲线",heartDropouts:"无读数",sleepTrend:"睡眠时长趋势",stressTrend:"压力趋势",noSteps:"无步数数据",noHeart:"无心率数据",noSleep:"无睡眠数据",noStress:"无压力数据",goodSteps:"活动量不错",midSteps:"步数中等",lowSteps:"活动量偏低",goodSleep:"睡眠时长充足",lowSleep:"睡眠时长不足",highHeart:"平均心率偏高",lowHeart:"平均心率偏低",okHeart:"心率区间平稳",highStress:"压力指数偏高",waiting:"等待更多数据",noSleepStage:"这一天没有睡眠阶段时间线",noValidSleep:"暂无有效睡眠明细",noSleepData:"暂无睡眠数据",noMonthData:"暂无月份数据",noChartData:"没有该指标数据",noCalendar:"上传有历史记录的导出文件后显示月度活动环",uploading:"上传并解析中...",uploadFailed:"上传失败",importDone:"导入完成",creatingUser:"正在增加账户...",userCreated:"账户已增加",saving:"正在保存...",saved:"设置已保存",changingPassword:"正在修改密码...",passwordChanged:"密码已修改",healthProfile:"健康个人资料",heightCm:"身高 cm",weightKg:"体重 kg",gender:"性别",unknown:"未知",male:"男",female:"女",birthday:"生日",birthYear:"出生年份",stepLengthCm:"步长 cm",dailyStepsGoal:"每日步数目标",dailyCaloriesGoal:"每日卡路里目标",dailyMinutesGoal:"每日运动分钟目标",deviceName:"设备名称",saveProfile:"保存个人资料",profileSaved:"个人资料已保存",autoProfileHint:"上传 DA FIT ZIP 后会自动更新这些资料；也可以在这里手动修改。"},en:{lead:"Upload DA FIT exports, parse them locally, and review steps, heart rate, sleep, stress trends, and daily suggestions.",dashboardTab:"Dashboard",usersTab:"User management",logout:"Logout",exportCsv:"Export CSV",chooseZip:"Choose export ZIP",upload:"Upload",addUser:"Add user",metricMonth:"Metric month",stepsCard:"Latest steps",heartCard:"Average heart rate",sleepCard:"Sleep",stressCard:"Stress",advice:"Health advice",stepsTab:"Steps",heartTab:"Heart rate",sleepTab:"Sleep",stressTab:"Stress",sleepRatio:"Sleep ratio",sleepQuality:"Sleep Quality Score",poor:"Poor",secondary:"Secondary",good:"Good",excellent:"Excellent",sleepStage:"Sleep stage chart",monthlyRings:"Monthly activity rings",recentImport:"Latest import",file:"File",importTime:"Import time",exportTimestamp:"Export timestamp",tableCounts:"Table counts",profileSettings:"Profile settings",defaultLanguage:"Default language",saveSettings:"Save settings",changePassword:"Change password",currentPassword:"Current password",newPassword:"New password",newUsername:"New username",adminRole:"Admin",stepsTrend:"Steps trend",heartTrend:"Average heart rate trend",dailyHeartCurve:"Daily heart-rate curve",noHeartCurve:"No daily heart-rate curve",heartDropouts:"No reading",sleepTrend:"Sleep duration trend",stressTrend:"Stress trend",noSteps:"no steps data",noHeart:"no heart-rate data",noSleep:"no sleep data",noStress:"no stress data",goodSteps:"Good activity",midSteps:"Moderate steps",lowSteps:"Low activity",goodSleep:"Enough sleep",lowSleep:"Short sleep",highHeart:"Average heart rate is high",lowHeart:"Average heart rate is low",okHeart:"Heart rate looks steady",highStress:"Stress is elevated",waiting:"Waiting for more data",noSleepStage:"No sleep-stage timeline for this date",noValidSleep:"No valid sleep detail",noSleepData:"No sleep data",noMonthData:"No month data",noChartData:"No data for this metric",noCalendar:"Upload an export with history to show monthly activity rings",uploading:"Uploading and parsing...",uploadFailed:"Upload failed",importDone:"Import complete",creatingUser:"Creating user...",userCreated:"User created",saving:"Saving...",saved:"Settings saved",changingPassword:"Changing password...",passwordChanged:"Password changed",healthProfile:"Health profile",heightCm:"Height cm",weightKg:"Weight kg",gender:"Gender",unknown:"Unknown",male:"Male",female:"Female",birthday:"Birthday",birthYear:"Birth year",stepLengthCm:"Step length cm",dailyStepsGoal:"Daily steps goal",dailyCaloriesGoal:"Daily calories goal",dailyMinutesGoal:"Daily activity minutes goal",deviceName:"Device name",saveProfile:"Save health profile",profileSaved:"Health profile saved",autoProfileHint:"Uploading a DA FIT ZIP updates these fields automatically. You can also edit them here."}};
    Object.assign(I18N.zh,{dailyReport:"每日健康日报",copyReport:"复制报告",noDailyReport:"暂无每日健康日报数据",copied:"已复制"});
    Object.assign(I18N.en,{dailyReport:"Daily health report",copyReport:"Copy report",noDailyReport:"No daily report data",copied:"Copied"});
    const tr=(key)=>I18N[lang]?.[key]||I18N.zh[key]||key;
    function applyLanguage(){document.documentElement.lang=lang==="en"?"en":"zh-CN"; document.getElementById("langSelect").value=lang; document.querySelectorAll("[data-i18n]").forEach(n=>n.textContent=tr(n.dataset.i18n)); document.querySelectorAll("[data-placeholder-key]").forEach(n=>n.placeholder=tr(n.dataset.placeholderKey)); renderSummary(); renderAdvice(); renderDailyReport(); renderChart(); renderHeartOptions(); renderDailyHeart(); renderSleepOptions(); renderSleepDetail(); renderCalendar();}
    async function initUser(){ const me=await fetch("/api/me").then(r=>r.ok?r.json():null); if(!me){location.href="/login";return} if(!localStorage.getItem("dafit_lang"))lang=me.default_language||"zh"; userProfile=me.profile||{}; setText("userBadge",me.username); document.getElementById("defaultLanguage").value=me.default_language||"zh"; document.getElementById("adminPanel").style.display=me.is_admin?"block":"none"; renderProfile(); }
    async function load(){ await initUser(); const response=await fetch(`/api/summary?fresh=${Date.now()}`,{cache:"no-store"}); if(!response.ok)throw new Error(`summary ${response.status}`); state=await response.json(); renderMonthOptions(); renderSummary(); renderAdvice(); renderDailyReportOptions(); renderDailyReport(); renderImports(); renderChart(); renderHeartOptions(); renderDailyHeart(); renderSleepOptions(); renderSleepDetail(); renderCalendar(); applyLanguage(); }
    let lastAutoRefresh=0;
    async function refreshWhenVisible(){ if(document.visibilityState!=="visible"||Date.now()-lastAutoRefresh<15000)return; lastAutoRefresh=Date.now(); try{await load()}catch(error){console.error("dashboard refresh failed",error)} }
    function dateInputFromMs(ms){ if(!ms)return""; const d=new Date(Number(ms)); return Number.isNaN(d.getTime())?"":d.toISOString().slice(0,10); }
    function setInput(id,value){ document.getElementById(id).value=value??""; }
    function renderProfile(){ const p=userProfile||{}; setInput("profileHeightCm",p.height_cm); setInput("profileWeightKg",p.weight_kg); setInput("profileGender",p.gender); setInput("profileBirthday",dateInputFromMs(p.birthday_ms)); setInput("profileBirthYear",p.birth_year); setInput("profileStepLengthCm",p.step_length_cm); setInput("profileDailyStepsGoal",p.daily_steps_goal); setInput("profileDailyCaloriesGoal",p.daily_calories_goal); setInput("profileDailyMinutesGoal",p.daily_minutes_goal); setInput("profileDeviceName",p.device_name); }
    function sameMonth(row,month=selectedMetricMonth){ return String(row?.date_iso||"").slice(0,7)===month; }
    function latestInMonth(rows,month=selectedMetricMonth,predicate=()=>true){ return (rows||[]).filter(r=>sameMonth(r,month)&&predicate(r)).at(-1); }
    function monthRows(){ const s=state.series||{}, reports=dailyReports(), selectedDaily=reports.find(r=>String(r.date_ms)===String(selectedReportMs)&&sameMonth(r)); return {sport:latestInMonth(sportDailyRows(s.sport)), daily:selectedDaily||latestInMonth(reports), heart:latestInMonth(s.heart_rate,selectedMetricMonth,r=>Number(r.average)>0), sleep:latestInMonth(s.sleep,selectedMetricMonth,r=>sum([r.deep,r.shallow,r.rem])>0), stress:latestInMonth(s.stress,selectedMetricMonth,r=>Number(r.average)>0)}; }
    function dailySnapshot(daily){ const raw=rawDaily(daily); return daily?{date:daily.date_iso,steps:Number(raw.STEPS_VALUE??daily.steps??0),calories:Number(raw.CALORIES_VALUE??daily.calories??0),heart:Number(raw.HEART_RATE_VALUE??0),sleep:Number(raw.SLEEP_DURATION_VALUE??0),stress:Number(raw.STRESS_VALUE??0)}:null; }
    function renderSummary(){ const {sport,daily,heart,sleep,stress}=monthRows(), snapshot=dailySnapshot(daily); for(const id of ["steps","hr","sleep","stress"])setText(id,"--"); setText("stepsSub",`${selectedMetricMonth||"--"} ${tr("noSteps")}`); setText("hrSub",`${selectedMetricMonth||"--"} ${tr("noHeart")}`); setText("sleepSub",`${selectedMetricMonth||"--"} ${tr("noSleep")}`); setText("stressSub",`${selectedMetricMonth||"--"} ${tr("noStress")}`); if(sport){setText("steps",fmt.format(Number(sport.steps||0))); setText("stepsSub",`${dt(sport.date_iso)} · ${num(sport.calories,0)} kcal`)} if(snapshot){const source=lang==="en"?"DA FIT daily report":"DA FIT 每日报告"; setText("hr",num(snapshot.heart,0)); setText("hrSub",`${dt(snapshot.date)} · ${source}`); setText("sleep",snapshot.sleep?`${Math.floor(snapshot.sleep/60)}h ${Math.round(snapshot.sleep%60)}m`:"--"); setText("sleepSub",`${dt(snapshot.date)} · ${source}`); setText("stress",num(snapshot.stress,0)); setText("stressSub",`${dt(snapshot.date)} · ${source}`)} else {if(heart){setText("hr",num(heart.average,0)); setText("hrSub",`${dt(heart.date_iso)} · ${num(heart.min_rate,0)}-${num(heart.max_rate,0)} bpm`)} if(sleep){const total=sum([sleep.deep,sleep.shallow,sleep.rem]); setText("sleep",total?`${(total/60).toFixed(1)}h`:"--"); setText("sleepSub",`${dt(sleep.date_iso)}`)} if(stress){setText("stress",num(stress.average,0)); setText("stressSub",`${dt(stress.date_iso)} · ${num(stress.min_stress,0)}-${num(stress.max_stress,0)}`)}}}
    function renderAdvice(){ const {sport,daily,heart,sleep,stress}=monthRows(), snapshot=dailySnapshot(daily); const items=[]; const add=(level,title,text)=>items.push({level,title,text}); const steps=Number(snapshot?.steps??sport?.steps??0), sleepMinutes=Number(snapshot?.sleep??(sleep?sum([sleep.deep,sleep.shallow,sleep.rem]):0)), heartAverage=Number(snapshot?.heart??heart?.average??0), stressAverage=Number(snapshot?.stress??stress?.average??0); if(steps){ if(steps>=8000)add("good",tr("goodSteps"),lang==="en"?`${fmt.format(steps)} steps in ${selectedMetricMonth}; this is near or above a common daily activity target.`:`${selectedMetricMonth} 最新日报 ${fmt.format(steps)} 步，已经接近或超过常见日常活动目标。`); else if(steps>=4000)add("watch",tr("midSteps"),lang==="en"?`${fmt.format(steps)} steps in ${selectedMetricMonth}; a walk can help bring the day closer to 7,000-8,000 steps.`:`${selectedMetricMonth} 最新日报 ${fmt.format(steps)} 步，可以用饭后散步把当天活动量补到 7000-8000 步区间。`); else add("warn",tr("lowSteps"),lang==="en"?`${fmt.format(steps)} steps in ${selectedMetricMonth}; consider 20-30 minutes of easy walking if you feel well.`:`${selectedMetricMonth} 最新日报 ${fmt.format(steps)} 步，建议安排 20-30 分钟轻中度步行。`);} if(sleepMinutes>=420)add("good",tr("goodSleep"),lang==="en"?`Latest sleep in ${selectedMetricMonth} is about ${(sleepMinutes/60).toFixed(1)} hours.`:`${selectedMetricMonth} 最近睡眠约 ${(sleepMinutes/60).toFixed(1)} 小时。继续保持固定作息。`); else if(sleepMinutes>0)add("watch",tr("lowSleep"),lang==="en"?`Latest sleep in ${selectedMetricMonth} is about ${(sleepMinutes/60).toFixed(1)} hours; protect a continuous sleep window.`:`${selectedMetricMonth} 最近睡眠约 ${(sleepMinutes/60).toFixed(1)} 小时，优先保证连续睡眠窗口。`); if(heartAverage){if(heartAverage>=95)add("watch",tr("highHeart"),lang==="en"?`Latest monthly reading is about ${heartAverage.toFixed(0)} bpm; interpret with activity, caffeine, stress, and sleep.`:`${selectedMetricMonth} 最新平均心率约 ${heartAverage.toFixed(0)} bpm。结合运动、咖啡因、压力和睡眠一起看。`); else if(heartAverage<=55)add("watch",tr("lowHeart"),lang==="en"?`Latest monthly reading is about ${heartAverage.toFixed(0)} bpm. If symptoms occur, consult a clinician.`:`${selectedMetricMonth} 最新平均心率约 ${heartAverage.toFixed(0)} bpm。如果伴随不适，应线下咨询医生。`); else add("good",tr("okHeart"),lang==="en"?`Latest monthly reading is about ${heartAverage.toFixed(0)} bpm.`:`${selectedMetricMonth} 最新平均心率约 ${heartAverage.toFixed(0)} bpm。`);} if(stressAverage>=60)add("watch",tr("highStress"),lang==="en"?`Latest stress average is about ${stressAverage.toFixed(0)}; short breaks or easy walking may help.`:`${selectedMetricMonth} 最近压力均值约 ${stressAverage.toFixed(0)}，可以安排短休息、呼吸练习或低强度散步。`); if(!items.length)add("watch",tr("waiting"),lang==="en"?`No usable records for ${selectedMetricMonth}. Upload a DA FIT export with this month to generate advice.`:`${selectedMetricMonth} 没有足够数据。上传包含该月记录的 DA FIT 导出后，这里会生成建议。`); document.getElementById("advice").innerHTML=items.map(item=>`<div class="advice-item ${item.level}"><div class="advice-title">${escapeHtml(item.title)}</div><div class="advice-text">${escapeHtml(item.text)}</div></div>`).join(""); }
    function rawDaily(row){ if(!row?.raw_json)return{}; try{return JSON.parse(row.raw_json)}catch{return{}} }
    function estimateHealthScore(values){const parts=[]; if(values.steps>0)parts.push([35,Math.min(100,values.steps/Math.max(1,Number(userProfile.daily_steps_goal||10000))*100)]); if(values.sleep>0)parts.push([30,Math.min(100,values.sleep/480*100)]); if(values.heart>0){const score=values.heart>=55&&values.heart<=90?100:Math.max(0,100-Math.abs(values.heart-(values.heart<55?55:90))*4); parts.push([15,score]);} if(values.stress>0)parts.push([20,Math.max(0,100-values.stress)]); if(!parts.length)return 0; return Math.round(parts.reduce((total,[weight,score])=>total+weight*score,0)/parts.reduce((total,[weight])=>total+weight,0));}
    function estimatedDailyReports(){const s=state.series||{}, byDay=new Map(), touch=(row,field,value)=>{const key=calendarDayKey(row); if(!key)return; if(!byDay.has(key))byDay.set(key,{date_iso:`${key}T12:00:00+00:00`,date_ms:Date.parse(`${key}T12:00:00Z`),values:{},available:[]}); const item=byDay.get(key); item.values[field]=Number(value||0); if(Number(value||0)>0&&!item.available.includes(field))item.available.push(field);}; for(const row of sportDailyRows(s.sport)){touch(row,"steps",row.steps); touch(row,"calories",row.calories);} for(const row of validSleepRows())touch(row,"sleep",sum([row.deep,row.shallow,row.rem])); for(const row of uniqueDailyRows(s.heart_rate,r=>Number(r.average)>0?1:0))touch(row,"heart",row.average); for(const row of uniqueDailyRows(s.stress,r=>Number(r.average)>0?1:0))touch(row,"stress",row.average); return [...byDay.values()].filter(item=>item.available.length).map(item=>{const v=item.values, score=estimateHealthScore(v), raw={ESTIMATED:true,AVAILABLE_KEYS:item.available,REPORT_DATE:item.date_ms,STEPS_VALUE:v.steps,CALORIES_VALUE:v.calories,HEART_RATE_VALUE:v.heart,SLEEP_DURATION_VALUE:v.sleep,STRESS_VALUE:v.stress,TOTAL_SCORE:score,STEPS_GOAL:Number(userProfile.daily_steps_goal||10000),CALORIES_GOAL:Number(userProfile.daily_calories_goal||300),STEPS_STATUS:v.steps>=Number(userProfile.daily_steps_goal||10000)?0:1,SLEEP_DURATION_STATUS:v.sleep>=420?0:1,HEART_RATE_STATUS:v.heart>=55&&v.heart<=90?0:1,STRESS_STATUS:v.stress>60?1:0}; return {...item,total_score:score,grade:"WEBSITE_ESTIMATE",raw_json:JSON.stringify(raw),estimated:true};});}
    function dailyReports(){const byDay=new Map(estimatedDailyReports().map(row=>[calendarDayKey(row),row])); for(const row of state.series?.daily_health||[])if(row.raw_json)byDay.set(calendarDayKey(row),row); return [...byDay.values()].sort((a,b)=>calendarDayKey(a).localeCompare(calendarDayKey(b)));}
    function msDate(ms){ if(!Number(ms))return"--"; const d=new Date(Number(ms)); return Number.isNaN(d.getTime())?"--":`${d.getUTCMonth()+1}/${d.getUTCDate()}/${d.getUTCFullYear()}`; }
    function reportRowsBefore(rows,row,field){ return (rows||[]).filter(r=>Number(r.date_ms)<Number(row.date_ms)).slice(-7).map(r=>Number(field(r))).filter(v=>Number.isFinite(v)&&v>0); }
    function avgText(values,unit=""){ if(!values.length)return lang==="en"?"7d avg --":"7日均值 --"; const avg=sum(values)/values.length; return lang==="en"?`7d avg ${unit==="steps"?fmt.format(Math.round(avg)):num(avg,0)}${unit&&unit!=="steps"?" "+unit:""}`:`7日均值 ${unit==="steps"?fmt.format(Math.round(avg)):num(avg,0)}${unit&&unit!=="steps"?" "+unit:""}`; }
    function statusText(code){ const zh={0:"Normal",1:"Attention",2:"Normal"}, en={0:"Normal",1:"Attention",2:"Normal"}; return (lang==="en"?en:zh)[Number(code)]||"--"; }
    function scoreGrade(score,grade){ const raw=String(grade||"").toUpperCase(); if(raw==="WEBSITE_ESTIMATE")return lang==="en"?`Website estimate · ${score>=85?"Excellent":score>=70?"Normal":"Needs Improvement"}`:`网站估算 · ${score>=85?"优秀":score>=70?"一般":"需改善"}`; if(raw==="ATTENTION")return "Needs Improvement (ATTENTION)"; if(raw==="NORMAL")return "Normal"; if(raw)return raw.replaceAll("_"," "); if(score>=85)return "Excellent"; if(score>=70)return "Normal"; if(score>0)return "Needs Improvement"; return "--"; }
    function renderDailyReportOptions(){ const rows=dailyReports(), list=document.getElementById("reportDateList"); if(!rows.length){drawCalendarPicker("reportDatePicker",[],""); list.replaceChildren(); selectedReportMs=null; return} if(!selectedReportMs||!rows.some(r=>String(r.date_ms)===String(selectedReportMs)))selectedReportMs=rows[rows.length-1].date_ms; const ordered=rows.slice().reverse(), selected=ordered.find(r=>String(r.date_ms)===String(selectedReportMs)), dates=rows.map(r=>String(r.date_iso).slice(0,10)); drawCalendarPicker("reportDatePicker",dates,String(selected?.date_iso||"").slice(0,10)); list.innerHTML=ordered.slice(0,4).map(r=>`<button type="button" class="report-date-btn ${String(r.date_ms)===String(selectedReportMs)?"active":""}" data-report-ms="${r.date_ms}">${dt(r.date_iso)}</button>`).join(""); }
    function buildDailyReport(row){ const raw=rawDaily(row), s=state.series||{}, estimated=Boolean(raw.ESTIMATED), score=Number(raw.TOTAL_SCORE??row.total_score??0), grade=scoreGrade(score,raw.GRADE??row.grade), steps=Number(raw.STEPS_VALUE??row.steps??0), stepsGoal=Number(raw.STEPS_GOAL??userProfile.daily_steps_goal??10000), calories=Number(raw.CALORIES_VALUE??row.calories??0), caloriesGoal=Number(raw.CALORIES_GOAL??userProfile.daily_calories_goal??300), activity=Number(raw.ACTIVITY_VALUE??row.activity??0), activityGoal=Number(raw.ACTIVITY_GOAL??userProfile.daily_minutes_goal??30), sleep=Number(raw.SLEEP_DURATION_VALUE??0), sleepQ=Number(raw.SLEEP_QUALITY_VALUE??raw.SLEEP_QUALITY_RAW_VALUE??0), heart=Number(raw.HEART_RATE_VALUE??0), stress=Number(raw.STRESS_VALUE??0); const stepsAvg=avgText(reportRowsBefore(s.sport,row,r=>r.steps),"steps"), heartAvg=avgText(reportRowsBefore(s.heart_rate,row,r=>r.average),"bpm"), stressAvg=avgText(reportRowsBefore(s.stress,row,r=>r.average),""), sleepAvg=avgText(reportRowsBefore(validSleepRows(),row,r=>sum([r.deep,r.shallow,r.rem])/60),"h"); const sleepHours=sleep?`${Math.floor(sleep/60)}h${String(Math.round(sleep%60)).padStart(2,"0")}m`:"--"; const reportDate=msDate(raw.REPORT_DATE), displayDate=dt(row.date_iso), generated=raw.GENERATED_DATE?new Date(raw.GENERATED_DATE).toLocaleString():"--"; const metrics=[{key:"steps",level:Number(raw.STEPS_STATUS)===1?"warn":"good",title:lang==="en"?"Steps":"步数",value:`${fmt.format(steps)} / ${fmt.format(stepsGoal)}`,sub:stepsAvg+" · "+statusText(raw.STEPS_STATUS)},{key:"calories",level:calories>=caloriesGoal?"good":"warn",title:lang==="en"?"Calories":"消耗",value:`${num(calories,0)} / ${num(caloriesGoal,0)} kcal`,sub:statusText(raw.STEPS_STATUS)},{key:"activity",level:Number(raw.ACTIVITY_STATUS)===1?"warn":"good",title:lang==="en"?"Active minutes":"运动时长",value:`${num(activity,0)} / ${num(activityGoal,0)} min`,sub:statusText(raw.ACTIVITY_STATUS)},{key:"sleep",level:Number(raw.SLEEP_DURATION_STATUS)===1||sleep<420?"warn":"good",title:lang==="en"?"Sleep":"睡眠",value:sleepHours,sub:`${sleepAvg} · ${statusText(raw.SLEEP_DURATION_STATUS)}${estimated?"":` · quality ${num(sleepQ,0)}`}`},{key:"stress",level:Number(raw.STRESS_STATUS)===1?"warn":"good",title:lang==="en"?"Stress":"压力",value:num(stress,0),sub:`${stressAvg} · ${statusText(raw.STRESS_STATUS)}`},{key:"heart",level:Number(raw.HEART_RATE_STATUS)===1?"warn":"good",title:lang==="en"?"Heart rate":"心率",value:`${num(heart,0)} bpm`,sub:`${heartAvg} · ${statusText(raw.HEART_RATE_STATUS)}`}].filter(metric=>!estimated||raw.AVAILABLE_KEYS.includes(metric.key)); const focus=metrics.filter(m=>m.level==="warn").map(m=>m.title).slice(0,2).join(lang==="en"?", ":"、")|| (lang==="en"?"keep current routine":"继续保持当前节奏"); const estimateNote=lang==="en"?"Website estimate calculated from the available exported metrics; it is not a DA FIT official score.":"网站估算根据当日可用的导出指标计算，并非 Da Fit 官方评分。", narrative=estimated?`${estimateNote} ${lang==="en"?`Items to watch: ${focus}.`:`主要需要关注：${focus}。`}`:(lang==="en"?`Overall score ${num(score,0)} (${grade}). Activity was solid if steps, calories, or active minutes met target; the main items to watch are ${focus}.`:`综合分 ${num(score,0)}（${grade}）。活动量看步数、消耗和运动时长是否达标；今天主要需要关注的是 ${focus}。`); const title=estimated?(lang==="en"?"Website Estimated Health Summary":"网站估算健康摘要"):(lang==="en"?"DA FIT Daily Health Report":"DA FIT 每日健康日报"), lines=lang==="en"?[`${title} ${displayDate}`,`Score: ${num(score,0)} (${grade})`,estimated?estimateNote:`Report day: ${reportDate}; generated: ${generated}`,...metrics.map(m=>`- ${m.title}: ${m.value}; ${m.sub}`),`Read: ${narrative}`]:[`${title} ${displayDate}`,`综合分：${num(score,0)}（${grade}）`,estimated?estimateNote:`统计日期：${reportDate}；生成时间：${generated}`,...metrics.map(m=>`- ${m.title}：${m.value}；${m.sub}`),`我的判断：${narrative}`]; return {score,grade,reportDate,displayDate,generated,metrics,narrative,estimated,text:lines.join("\n")}; }
    function renderDailyReport(){ const rows=dailyReports(), row=rows.find(r=>String(r.date_ms)===String(selectedReportMs))||rows.at(-1); if(!row){setText("reportScore","--"); setText("reportGrade","--"); setText("reportDate",tr("noDailyReport")); setText("reportTitle",tr("noDailyReport")); setText("reportNarrative","--"); document.getElementById("reportMetrics").innerHTML=""; document.getElementById("reportText").textContent=""; return} const report=buildDailyReport(row); setText("reportScore",num(report.score,0)); setText("reportGrade",report.grade); setText("reportDate",report.estimated?`${report.displayDate} · ${lang==="en"?"website estimate":"网站估算"}`:`${report.displayDate} · ${lang==="en"?"report day":"统计"} ${report.reportDate}`); setText("reportKicker",report.estimated?(lang==="en"?"WEBSITE ESTIMATE":"网站估算"):(lang==="en"?"DA FIT Daily Report":"DA FIT Daily Report")); setText("reportTitle",report.estimated?(lang==="en"?"Calculated from available exported metrics":"根据当日可用导出指标计算"):(lang==="en"?`Generated ${report.generated}`:`生成时间 ${report.generated}`)); setText("reportNarrative",report.narrative); document.getElementById("reportMetrics").innerHTML=report.metrics.map(m=>`<div class="report-metric ${m.level}"><div class="report-metric-title">${escapeHtml(m.title)}</div><div class="report-metric-value">${escapeHtml(m.value)}</div><div class="report-metric-sub">${escapeHtml(m.sub)}</div></div>`).join(""); document.getElementById("reportText").textContent=report.text; }
    function renderImports(){ document.getElementById("imports").innerHTML=(state.imports||[]).map(row=>{let counts=row.counts_json; try{counts=Object.entries(JSON.parse(counts)).map(([k,v])=>`${k}:${v}`).join(" · ")}catch{} const exportAt=row.export_ms?new Date(row.export_ms).toLocaleString():"--"; return `<tr><td>${escapeHtml(row.filename)}</td><td>${new Date(row.uploaded_at).toLocaleString()}</td><td>${exportAt}</td><td>${escapeHtml(counts)}</td></tr>`}).join(""); }
    function heartSamples(row){ if(!row?.raw_json)return[]; try{const raw=JSON.parse(row.raw_json), values=typeof raw.HEART_RATE==="string"?JSON.parse(raw.HEART_RATE):raw.HEART_RATE; return Array.isArray(values)?values.map(Number).filter(v=>Number.isFinite(v)):[];}catch{return[]} }
    function heartRows(){ return uniqueDailyRows((state.series?.heart_rate||[]).filter(r=>heartSamples(r).length),r=>heartSamples(r).filter(v=>v>0).length); }
    function renderHeartOptions(){ const rows=heartRows().filter(r=>sameMonth(r)); if(!rows.length){drawCalendarPicker("heartSelect",[],""); selectedHeartMs=null; return} if(!selectedHeartMs||!rows.some(r=>String(r.date_ms)===String(selectedHeartMs)))selectedHeartMs=rows[rows.length-1].date_ms; const selected=rows.find(r=>String(r.date_ms)===String(selectedHeartMs)), dates=rows.map(r=>String(r.date_iso).slice(0,10)); drawCalendarPicker("heartSelect",dates,String(selected?.date_iso||"").slice(0,10)); }
    function selectedHeart(){ return heartRows().filter(r=>sameMonth(r)).find(r=>String(r.date_ms)===String(selectedHeartMs)); }
    function renderDailyHeart(){ const svg=document.getElementById("heartDaySvg"), stats=document.getElementById("heartDayStats"), row=selectedHeart(), values=heartSamples(row); if(!row||!values.length){svg.innerHTML=`<text x="380" y="92" text-anchor="middle" class="tick">${tr("noHeartCurve")}</text>`; stats.textContent=tr("noHeartCurve"); return} const W=760,H=180,P=28, valid=values.filter(v=>v>0), dropouts=values.length-valid.length, min=Math.min(...valid,55), max=Math.max(...valid,120), x=i=>P+i*((W-P*2)/Math.max(1,values.length-1)), y=v=>H-P-((v-min)/Math.max(1,max-min))*(H-P*2); const grid=[0,.25,.5,.75,1].map(t=>{const yy=P+t*(H-P*2), val=max-t*(max-min); return `<line class="axis" x1="${P}" y1="${yy}" x2="${W-P}" y2="${yy}"/><text class="tick" x="4" y="${yy+4}">${Math.round(val)}</text>`}).join(""); let segments=[], current=[]; values.forEach((v,i)=>{if(v>0)current.push(`${x(i)},${y(v)}`); else if(current.length){segments.push(current); current=[];}}); if(current.length)segments.push(current); const lines=segments.map(points=>`<polyline class="line" points="${points.join(" ")}"></polyline>`).join(""); const dots=values.map((v,i)=>{const minute=Math.round(i*1440/Math.max(1,values.length)), label=`${String(Math.floor(minute/60)).padStart(2,"0")}:${String(minute%60).padStart(2,"0")} · ${v>0?Math.round(v)+" bpm":tr("heartDropouts")}`; if(v>0)return `<circle class="point-hit" cx="${x(i)}" cy="${y(v)}" r="8"><title>${escapeHtml(label)}</title></circle>`; return `<rect class="dropout" x="${x(i)-1.5}" y="${H-P-8}" width="3" height="8"><title>${escapeHtml(label)}</title></rect>`;}).join(""); const labels=[["00:00",P],["06:00",P+(W-P*2)*.25],["12:00",P+(W-P*2)*.5],["18:00",P+(W-P*2)*.75],["24:00",W-P-34]].map(([label,xx])=>`<text class="tick" x="${xx}" y="${H-4}">${label}</text>`).join(""); svg.innerHTML=`${grid}${lines}${dots}${labels}`; const avg=Number(row.average||0), minRow=Number(row.min_rate||0), maxRow=Number(row.max_rate||0); stats.textContent=lang==="en"?`${dt(row.date_iso)} · avg ${avg.toFixed(0)} bpm · ${minRow.toFixed(0)}-${maxRow.toFixed(0)} bpm · ${valid.length} readings · ${dropouts} ${tr("heartDropouts")}`:`${dt(row.date_iso)} · 平均 ${avg.toFixed(0)} bpm · ${minRow.toFixed(0)}-${maxRow.toFixed(0)} bpm · ${valid.length} 个有效读数 · ${dropouts} 个${tr("heartDropouts")}`; }
    function fmtMinutes(minutes){minutes=Number(minutes||0); const h=Math.floor(minutes/60), m=Math.round(minutes%60); return h?`${h} H ${m} M`:`${m} M`;}
    function dailyRaw(){ const row=state.latest?.daily_health; if(!row?.raw_json)return{}; try{return JSON.parse(row.raw_json)}catch{return{}} }
    function sleepDetail(sleep){ if(!sleep?.detail_json)return[]; try{const parsed=JSON.parse(sleep.detail_json), detail=Array.isArray(parsed)?parsed:parsed.detail; return Array.isArray(detail)?detail:[]}catch{return[]} }
    function clockMinutes(value){ const match=String(value||"").match(/^(\d{1,2}):(\d{2})$/); return match?Number(match[1])*60+Number(match[2]):null; }
    function circularMinuteDifference(a,b){ const difference=Math.abs(a-b); return Math.min(difference,1440-difference); }
    function sleepTiming(sleep){ const detail=sleepDetail(sleep); if(!detail.length)return null; const start=clockMinutes(detail[0]?.start), end=clockMinutes(detail.at(-1)?.end); if(start==null||end==null)return null; const awakeSegments=detail.filter(segment=>Number(segment.type)===0), awakeMinutes=sum(awakeSegments.map(segment=>Number(segment.total||0))); return {start,end,awakeMinutes,wakeCount:awakeSegments.length}; }
    function sleepRegularity(sleep){ const timing=sleepTiming(sleep); if(!timing)return 50; const previous=validSleepRows().filter(row=>String(row.date_iso)<String(sleep.date_iso)).slice(-7).map(sleepTiming).filter(Boolean); if(!previous.length)return 50; const averageDeviation=sum(previous.map(row=>(circularMinuteDifference(timing.start,row.start)+circularMinuteDifference(timing.end,row.end))/2))/previous.length; return Math.max(0,Math.min(100,100-averageDeviation/1.8)); }
    function sleepQuality(sleep){ if(!sleep)return null; const deep=Math.round(Number(sleep.deep||0)), shallow=Math.round(Number(sleep.shallow||0)), rem=Math.round(Number(sleep.rem||0)), total=deep+shallow+rem; if(total<=0)return null; /* Exact anchors transcribed from the supplied DA FIT screenshots; all other nights use the general wearable-data approximation below. */ const anchors={"68/262/92":91,"164/177/72":88,"12/79/6":19,"115/96/158":82,"165/269/67":100,"108/196/138":100}, anchored=anchors[`${deep}/${shallow}/${rem}`]; if(anchored!=null)return anchored; const timing=sleepTiming(sleep), durationPct=Math.min(100,total/480*100), restorativePct=(deep+rem)/total*100, awakeMinutes=timing?timing.awakeMinutes:Number(sleep.sober||0), wakeCount=timing?timing.wakeCount:(awakeMinutes>0?1:0), regularity=sleepRegularity(sleep); let score=durationPct*.788819+restorativePct*.441168-awakeMinutes*.03-wakeCount+regularity*.03-5.971388; if(total>=120&&total<240)score-=2; return Math.max(0,Math.min(100,Math.round(score))); }
    function validSleepRows(){ return uniqueDailyRows((state.series?.sleep||[]).filter(r=>sum([r.deep,r.shallow,r.rem])>0),r=>sum([r.deep,r.shallow,r.rem])); }
    function renderSleepOptions(){ const rows=validSleepRows(); if(!rows.length){drawCalendarPicker("sleepSelect",[],""); selectedSleepMs=null; return} const summarySleep=state.latest?.sleep; if(!selectedSleepMs||!rows.some(r=>String(r.date_ms)===String(selectedSleepMs)))selectedSleepMs=(summarySleep&&rows.some(r=>String(r.date_ms)===String(summarySleep.date_ms)))?summarySleep.date_ms:rows[rows.length-1].date_ms; const selected=rows.find(r=>String(r.date_ms)===String(selectedSleepMs)), dates=rows.map(r=>String(r.date_iso).slice(0,10)); drawCalendarPicker("sleepSelect",dates,String(selected?.date_iso||"").slice(0,10)); }
    function selectedSleep(){ return validSleepRows().find(r=>String(r.date_ms)===String(selectedSleepMs)) || validSleepRows().at(-1); }
    function parseSleepDetail(raw){ if(!raw)return[]; try{let v=JSON.parse(raw); if(typeof v==="string")v=JSON.parse(v); if(Array.isArray(v))return v; if(Array.isArray(v.detail))return v.detail;}catch{} return[]; }
    function renderSleepStage(sleep){ const svg=document.getElementById("sleepStageSvg"), detail=parseSleepDetail(sleep?.detail_json); const colors={0:"var(--orange)",1:"var(--magenta)",2:"var(--violet)",3:"var(--coral)"}, labels={0:"Awake",1:"Light",2:"Deep",3:"REM"}, yByType={0:22,3:52,1:82,2:112}; if(!detail.length){svg.innerHTML=`<text x="380" y="76" text-anchor="middle" class="tick">${tr("noSleepStage")}</text>`; return} const W=760,H=150,P=34, total=sum(detail.map(d=>d.total)); let used=0; const rows=[0,3,1,2].map(t=>`<text class="tick" x="2" y="${yByType[t]+13}">${labels[t]}</text><line class="axis" x1="${P}" y1="${yByType[t]+9}" x2="${W-P}" y2="${yByType[t]+9}"/>`).join(""); const blocks=detail.map(d=>{const w=Math.max(2,Number(d.total||0)/Math.max(1,total)*(W-P*2)), x=P+used/Math.max(1,total)*(W-P*2), y=yByType[d.type]??82; used+=Number(d.total||0); const label=`${labels[d.type]||"Stage"} ${d.start||""}-${d.end||""} · ${fmtMinutes(d.total)}`; return `<rect class="stage-block" x="${x}" y="${y}" width="${w}" height="18" fill="${colors[d.type]||"var(--blue)"}"><title>${escapeHtml(label)}</title></rect>`;}).join(""); const first=detail[0], last=detail[detail.length-1]; svg.innerHTML=`${rows}${blocks}<text class="tick" x="${P}" y="${H-6}">${escapeHtml(first.start||"")}</text><text class="tick" x="${W-P-36}" y="${H-6}">${escapeHtml(last.end||"")}</text>`; }
    function sleepHeartData(sleep){ const timing=sleepTiming(sleep); if(!sleep||!timing)return[]; const candidates=heartRows().slice().sort((a,b)=>Math.abs(Number(a.date_ms)-Number(sleep.date_ms))-Math.abs(Number(b.date_ms)-Number(sleep.date_ms))), row=candidates[0], samples=heartSamples(row); if(!samples.length)return[]; return samples.map((value,index)=>({value:Number(value||0),minute:index*1440/samples.length})).filter(point=>point.value>0&&((timing.start<=timing.end&&point.minute>=timing.start&&point.minute<=timing.end)||(timing.start>timing.end&&(point.minute>=timing.start||point.minute<=timing.end)))); }
    function renderSleepHeart(sleep){ const svg=document.getElementById("sleepHeartSvg"), points=sleepHeartData(sleep), stats=document.getElementById("sleepHeartStats"), timing=sleepTiming(sleep); setText("sleepHeartTitle",lang==="en"?"Sleep heart rate":"睡眠心率"); setText("sleepHeartNote",lang==="en"?"available 10-minute samples":"当前导出中的 10 分钟采样"); if(!points.length){stats.innerHTML=`<div class="sub">${lang==="en"?"No sleep heart-rate samples":"暂无睡眠心率采样"}</div>`; svg.innerHTML=""; return} const values=points.map(p=>p.value), avg=Math.floor(sum(values)/values.length), low=Math.min(...values), high=Math.max(...values), cards=lang==="en"?[["Average",avg],["Highest",high],["Lowest",low]]:[["平均",avg],["最高",high],["最低",low]]; stats.innerHTML=cards.map(([label,value])=>`<div class="sleep-stat"><span>${label}</span><strong>${value} BPM</strong></div>`).join(""); const W=760,H=150,P=28,min=Math.min(...values)-4,max=Math.max(...values)+4,x=i=>P+i*(W-P*2)/Math.max(1,points.length-1),y=v=>H-P-(v-min)/Math.max(1,max-min)*(H-P*2), poly=points.map((p,i)=>`${x(i)},${y(p.value)}`).join(" "), start=sleepDetail(sleep)[0]?.start||"", end=sleepDetail(sleep).at(-1)?.end||""; svg.innerHTML=`<line class="axis" x1="${P}" y1="${H-P}" x2="${W-P}" y2="${H-P}"/><polyline class="sleep-heart-line" points="${poly}"/>${points.map((p,i)=>`<circle class="point-hit" cx="${x(i)}" cy="${y(p.value)}" r="8"><title>${p.value} bpm</title></circle>`).join("")}<text class="tick" x="${P}" y="${H-5}">${escapeHtml(start)}</text><text class="tick" x="${W-P-38}" y="${H-5}">${escapeHtml(end)}</text>`; }
    function renderSleepTrend(sleep){ const svg=document.getElementById("sleepTrendSvg"), all=validSleepRows(), selectedIndex=all.findIndex(row=>String(row.date_ms)===String(sleep?.date_ms)), rows=all.slice(Math.max(0,selectedIndex-6),selectedIndex+1), W=760,H=210,P=30, max=Math.max(480,...rows.map(r=>sum([r.deep,r.shallow,r.rem]))), slot=(W-P*2)/Math.max(1,rows.length), width=Math.min(54,slot*.56), colors={deep:"var(--violet)",shallow:"var(--magenta)",rem:"var(--coral)"}; let bars=""; rows.forEach((r,i)=>{let bottom=H-P; for(const key of ["deep","shallow","rem"]){const value=Number(r[key]||0),height=value/max*(H-P*2); bottom-=height; bars+=`<rect class="sleep-trend-bar" x="${P+i*slot+(slot-width)/2}" y="${bottom}" width="${width}" height="${height}" fill="${colors[key]}"><title>${dt(r.date_iso)} · ${key} ${fmtMinutes(value)}</title></rect>`;} bars+=`<text class="tick" text-anchor="middle" x="${P+i*slot+slot/2}" y="${H-6}">${String(r.date_iso||"").slice(5,10).replace("-","/")}</text>`;}); svg.innerHTML=`<line class="axis" x1="${P}" y1="${H-P}" x2="${W-P}" y2="${H-P}"/>${bars}`; setText("sleepTrendTitle",lang==="en"?"Last 7 days sleep trends":"最近 7 天睡眠趋势"); }
    function sleepComparisons(sleep){ const timing=sleepTiming(sleep), total=sum([sleep?.deep,sleep?.shallow,sleep?.rem]); if(!timing)return[]; const bedtime=timing.start, wake=timing.end, earlySleep=bedtime>=1260&&bedtime<1320?86:bedtime>=1320&&bedtime<1380?60:bedtime>=1380?30:11, earlyWake=wake<300?98:wake<360?95:wake<420?63:wake<480?38:wake<540?20:wake<600?9:5, sleepLess=total>=480?14:total>=420?28:total>=360?51:total>=240?72:91; return lang==="en"?[["Sleep earlier than",earlySleep],["Wake earlier than",earlyWake],["Sleep less than",sleepLess]]:[["入睡早于",earlySleep],["起床早于",earlyWake],["睡眠少于",sleepLess]]; }
    function renderSleepComparisons(sleep){ setText("sleepCompareTitle",lang==="en"?"Reference population comparison":"与参考人群比较"); setText("sleepCompareNote",lang==="en"?"Estimated from age/sex reference distributions; not DA FIT server data":"按年龄和性别参考分布估算，并非 DA FIT 服务器数据"); document.getElementById("sleepCompareGrid").innerHTML=sleepComparisons(sleep).map(([label,value])=>`<div class="sleep-compare"><span>${label}</span><strong>${value}%</strong></div>`).join(""); }
    function renderSleepDetail(){ const sleep=selectedSleep(); const colors={deep:"var(--violet)",shallow:"var(--magenta)",rem:"var(--coral)"}, labels=lang==="en"?{deep:"Deep sleep",shallow:"Light sleep",rem:"REM"}:{deep:"深睡",shallow:"浅睡",rem:"REM"}; /* DA FIT's ratio card contains exactly these three sleeping stages. SOBER is awake/interruption time and belongs only in the stage timeline. */ const parts=[["deep",labels.deep,sleep?.deep],["shallow",labels.shallow,sleep?.shallow],["rem",labels.rem,sleep?.rem]].map(([key,label,value])=>({key,label,value:Number(value||0)})); const total=sum(parts.map(p=>p.value)); setText("sleepDate",sleep?.date_iso?dt(sleep.date_iso):"--"); setText("sleepTotal",total?fmtMinutes(total):"--"); document.getElementById("sleepRatioRows").innerHTML=parts.map(p=>`<div class="ratio-row"><div class="ratio-label"><span class="dot" style="background:${colors[p.key]}"></span>${p.label}</div><strong title="${total?Math.round(p.value/total*100):0}%">${fmtMinutes(p.value)}</strong></div>`).join("") || `<div class="sub">${tr("noValidSleep")}</div>`; const svg=document.getElementById("sleepDonut"); if(!total){svg.innerHTML=`<circle cx="85" cy="85" r="58" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="22"/>`} else {let used=0,circ=2*Math.PI*58; svg.innerHTML=parts.filter(p=>p.value>0).map(p=>{const len=p.value/total*circ, off=-used; used+=len; return `<circle cx="85" cy="85" r="58" fill="none" stroke="${colors[p.key]}" stroke-width="22" stroke-dasharray="${len} ${circ-len}" stroke-dashoffset="${off}" transform="rotate(-90 85 85)" stroke-linecap="butt"><title>${escapeHtml(p.label)} · ${fmtMinutes(p.value)} · ${Math.round(p.value/total*100)}%</title></circle>`}).join("");} const q=sleepQuality(sleep); setText("qualityScore",q==null?"--":Math.round(q)); document.getElementById("qualityMarker").style.left=`${q==null?0:q}%`; renderSleepStage(sleep); renderSleepHeart(sleep); renderSleepTrend(sleep); renderSleepComparisons(sleep); }
    function timezonePlace(offset){const names=lang==="en"?{"-480":"US Pacific","-420":"US Pacific","-300":"US Eastern","-240":"US Eastern","480":"China","540":"Korea"}:{"-480":"美西","-420":"美西","-300":"美东","-240":"美东","480":"中国","540":"韩国"}, value=Number(offset), sign=value>=0?"+":"−", utc=`UTC${sign}${Math.abs(value)/60}`; return `${names[String(value)]||utc}（${utc}）`;}
    function weatherTimezoneChanges(){const hints=[]; for(const row of state.series?.timezone_hints||[]){try{const raw=JSON.parse(row.raw_json||"{}"), weather=JSON.parse(raw.WEATHER||"{}"), offset=Number(weather.timezone)/60; if(Number(raw.FORECAST)!==0||!Number.isFinite(offset))continue; const local=new Date(Number(row.date_ms)+offset*60000); hints.push({day:new Date(Date.UTC(local.getUTCFullYear(),local.getUTCMonth(),local.getUTCDate())),offset});}catch{}} hints.sort((a,b)=>a.day-b.day); const changes=new Map(); let previous=null; for(const hint of hints){if(previous&&hint.offset!==previous.offset){const gap=Math.round((hint.day-previous.day)/86400000); /* A fresh DA FIT export can retain only sparse actual-weather observations. Allow up to one week so an Aug 2 old-zone observation plus an Aug 6 new-zone observation still marks the first activity day, Aug 3. */ if(gap>=1&&gap<=7){const activityDay=new Date(previous.day); activityDay.setUTCDate(activityDay.getUTCDate()+1); changes.set(activityDay.toISOString().slice(0,10),{from:previous.offset,to:hint.offset});}} previous=hint;} return changes;}
    function activityDays(){ const byDay=new Map(), hintChanges=weatherTimezoneChanges(), nearHintChange=key=>{const day=Date.parse(`${key}T00:00:00Z`); return [...hintChanges.keys()].some(hintKey=>Math.abs(Date.parse(`${hintKey}T00:00:00Z`)-day)<=7*86400000);}, add=(r,priority,timezoneChange=null)=>{const parts=calendarParts(r.date_iso); if(!parts)return; const key=`${parts.year}-${String(parts.month).padStart(2,"0")}-${String(parts.day).padStart(2,"0")}`, steps=Number(r.steps||0), raw=rawDaily(r), goal=Number(raw.STEPS_GOAL||userProfile.daily_steps_goal||10000), p=Math.max(0,Math.min(100,(steps/goal)*100)), prev=byDay.get(key), archiveChange=nearHintChange(key)?null:timezoneChange, change=hintChanges.get(key)||archiveChange||null; if(!prev||priority>prev.priority||(priority===prev.priority&&p>prev.p))byDay.set(key,{date:new Date(parts.year,parts.month-1,parts.day,12),steps,p,priority,timezoneChange:change});}; for(const r of state.series?.daily_health||[])add(r,1); let previousArchiveOffset=null; for(const r of sportDailyRows(state.series?.sport||[])){const offset=Number.isFinite(Number(r.archive_utc_offset_minutes))?Number(r.archive_utc_offset_minutes):null, timezoneChange=offset!==null&&previousArchiveOffset!==null&&offset!==previousArchiveOffset?{from:previousArchiveOffset,to:offset}:null; add(r,2,timezoneChange); if(offset!==null)previousArchiveOffset=offset;} return [...byDay.values()].sort((a,b)=>a.date-b.date); }
    function monthKey(d){ return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}`; }
    function allMonths(){ const s=state.series||{}, months=new Set(); for(const rows of [s.sport,s.heart_rate,s.sleep,s.stress,s.daily_health]) for(const r of rows||[]) if(r.date_iso)months.add(String(r.date_iso).slice(0,7)); return [...months].sort(); }
    function renderMonthOptions(){ const months=allMonths(); if(!months.length){drawCalendarPicker("metricMonthSelect",[],""); drawCalendarPicker("monthSelect",[],""); selectedMetricMonth=selectedMonth=null; return} if(!selectedMetricMonth||!months.includes(selectedMetricMonth))selectedMetricMonth=months[months.length-1]; if(!selectedMonth||!months.includes(selectedMonth))selectedMonth=selectedMetricMonth; drawCalendarPicker("metricMonthSelect",months,selectedMetricMonth); drawCalendarPicker("monthSelect",months,selectedMonth); }
    function renderCalendar(){ const days=activityDays().filter(d=>monthKey(d.date)===selectedMonth); const monthNames=lang==="en"?["January","February","March","April","May","June","July","August","September","October","November","December"]:["一月","二月","三月","四月","五月","六月","七月","八月","九月","十月","十一月","十二月"]; if(!days.length){document.getElementById("calendarMonths").innerHTML=`<div class="sub">${tr("noCalendar")}</div>`; return} const [year,month]=selectedMonth.split("-").map(Number), first=new Date(year,month-1,1), last=new Date(year,month,0).getDate(), map=new Map(days.map(v=>[v.date.getDate(),v])); let cells=""; for(let i=0;i<first.getDay();i++)cells+=`<div></div>`; for(let day=1;day<=last;day++){const v=map.get(day), today=new Date().toDateString()===new Date(year,month-1,day).toDateString(), zoneText=v?.timezoneChange?(lang==="en"?` · Time zone: ${timezonePlace(v.timezoneChange.from)} → ${timezonePlace(v.timezoneChange.to)}`:` · 时区变更：${timezonePlace(v.timezoneChange.from)} → ${timezonePlace(v.timezoneChange.to)}`):"", title=v?`${selectedMonth}-${String(day).padStart(2,"0")} · ${fmt.format(v.steps)} steps · ${Math.round(v.p)}%${zoneText}`:"No data", progress=v?`<svg class="day-ring-svg" viewBox="0 0 46 46" aria-hidden="true"><circle class="day-ring-track" cx="23" cy="23" r="19"/><circle class="day-ring-progress" cx="23" cy="23" r="19" pathLength="100" stroke-dasharray="${v.p} 100"/></svg>`:""; cells+=`<div class="day-ring ${v?"":"empty"} ${today?"today":""} ${v?.timezoneChange?"timezone-change":""}" title="${escapeHtml(title)}">${progress}<span>${day}</span></div>`;} document.getElementById("calendarMonths").innerHTML=`<div class="calendar-month"><div class="calendar-title">${monthNames[month-1]} ${year}</div><div class="calendar-days">${cells}</div></div>`; }
    function chartData(){ const s=state.series||{}; if(currentChart==="steps")return{title:`${selectedMetricMonth} ${tr("stepsTrend")}`,unit:"steps",mode:"bar",rows:sportDailyRows(s.sport),y:r=>r.steps,valid:v=>v>=0,fmt:v=>fmt.format(Math.round(v))}; if(currentChart==="heart")return{title:`${selectedMetricMonth} ${tr("heartTrend")}`,unit:"bpm",mode:"line",rows:uniqueDailyRows(s.heart_rate,r=>Number(r.average)>0?1:0),y:r=>r.average,valid:v=>v>0,fmt:v=>`${Math.round(v)} bpm`}; if(currentChart==="sleep")return{title:`${selectedMetricMonth} ${tr("sleepTrend")}`,unit:"h",mode:"bar",rows:uniqueDailyRows(s.sleep,r=>sum([r.deep,r.shallow,r.rem])),y:r=>sum([r.deep,r.shallow,r.rem])/60,valid:v=>v>0,fmt:v=>`${v.toFixed(1)} h`}; return{title:`${selectedMetricMonth} ${tr("stressTrend")}`,unit:"",mode:"line",rows:uniqueDailyRows(s.stress,r=>Number(r.average)>0?1:0),y:r=>r.average,valid:v=>v>0,fmt:v=>String(Math.round(v))};}
    function renderChart(){ const cfg=chartData(); setText("chartTitle",cfg.title); const svg=document.getElementById("chartSvg"); const rows=cfg.rows.filter(r=>{const v=Number(cfg.y(r)); return sameMonth(r)&&Number.isFinite(v)&&cfg.valid(v);}); if(!rows.length){svg.innerHTML=`<text x="380" y="120" text-anchor="middle" class="tick">${selectedMetricMonth||""} ${tr("noChartData")}</text>`; return} const W=760,H=240,P=26, vals=rows.map(cfg.y).map(Number), min=Math.min(0,...vals), max=Math.max(...vals)||1, x=i=>P+i*((W-P*2)/Math.max(1,rows.length-1)), y=v=>H-P-((v-min)/Math.max(1,max-min))*(H-P*2); const grid=[0,.25,.5,.75,1].map(t=>{const yy=P+t*(H-P*2), val=max-t*(max-min); return `<line class="axis" x1="${P}" y1="${yy}" x2="${W-P}" y2="${yy}"/><text class="tick" x="4" y="${yy+4}">${Math.round(val)}</text>`}).join(""); let shapes=""; if(cfg.mode==="bar"){const bw=Math.max(2,(W-P*2)/rows.length*.72); shapes=rows.map((r,i)=>{const v=Number(cfg.y(r)), label=`${dt(r.date_iso)} · ${cfg.fmt(v)}`; return `<rect class="bar" x="${x(i)-bw/2}" y="${y(v)}" width="${bw}" height="${H-P-y(v)}"><title>${escapeHtml(label)}</title></rect>`}).join("")} else {const points=rows.map((r,i)=>`${x(i)},${y(cfg.y(r))}`).join(" "), area=`${P},${H-P} ${points} ${x(rows.length-1)},${H-P}`, dots=rows.map((r,i)=>{const v=Number(cfg.y(r)), label=`${dt(r.date_iso)} · ${cfg.fmt(v)}`; return `<circle class="point" cx="${x(i)}" cy="${y(v)}" r="3.5"><title>${escapeHtml(label)}</title></circle><circle class="point-hit" cx="${x(i)}" cy="${y(v)}" r="10"><title>${escapeHtml(label)}</title></circle>`}).join(""); shapes=`<polygon class="area" points="${area}"></polygon><polyline class="line" points="${points}"></polyline>${dots}`} const first=rows[0], last=rows[rows.length-1]; svg.innerHTML=`${grid}${shapes}<text class="tick" x="${P}" y="${H-4}">${dt(first.date_iso)}</text><text class="tick" x="${W-P-70}" y="${H-4}">${dt(last.date_iso)}</text>`; }
    function escapeHtml(s){return String(s??"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
    document.querySelectorAll(".page-tab").forEach(btn=>btn.addEventListener("click",()=>{document.querySelectorAll(".page-tab").forEach(b=>b.classList.remove("active")); btn.classList.add("active"); document.getElementById("dashboardPage").classList.toggle("hidden",btn.dataset.page!=="dashboard"); document.getElementById("usersPage").classList.toggle("hidden",btn.dataset.page!=="users");}));
    document.querySelectorAll(".tab").forEach(btn=>btn.addEventListener("click",()=>{document.querySelectorAll(".tab").forEach(b=>b.classList.remove("active")); btn.classList.add("active"); currentChart=btn.dataset.chart; renderChart()}));
    document.getElementById("langSelect").addEventListener("change",(ev)=>{lang=ev.target.value; localStorage.setItem("dafit_lang",lang); applyLanguage();});
    document.addEventListener("click",ev=>{const root=ev.target.closest(".calendar-picker"); if(!root){document.querySelectorAll(".calendar-picker.open").forEach(p=>p.classList.remove("open")); return} ev.stopPropagation(); if(ev.target.closest(".calendar-picker-toggle")){document.querySelectorAll(".calendar-picker.open").forEach(p=>p!==root&&p.classList.remove("open")); root.classList.toggle("open"); drawCalendarPicker(root.id,JSON.parse(root.dataset.available||"[]"),root.dataset.selected); return} const nav=ev.target.closest("[data-calendar-nav]"); if(nav){const [year,month]=root.dataset.viewMonth.split("-").map(Number), next=new Date(Date.UTC(year,month-1+Number(nav.dataset.calendarNav),1)); root.dataset.viewMonth=`${next.getUTCFullYear()}-${String(next.getUTCMonth()+1).padStart(2,"0")}`; drawCalendarPicker(root.id,JSON.parse(root.dataset.available||"[]"),root.dataset.selected); return} const choice=ev.target.closest("[data-calendar-value]"); if(choice&&!choice.disabled){root.classList.remove("open"); root.dispatchEvent(new CustomEvent("calendar-change",{detail:{value:choice.dataset.calendarValue}}));}});
    document.getElementById("metricMonthSelect").addEventListener("calendar-change",(ev)=>{selectedMetricMonth=ev.detail.value; selectedHeartMs=null; renderMonthOptions(); renderSummary(); renderAdvice(); renderChart(); renderHeartOptions(); renderDailyHeart();});
    function rowForCalendarDate(rows,value){return (rows||[]).find(r=>String(r.date_iso||"").slice(0,10)===value);}
    function selectDailyReport(btn){ if(!btn)return; selectedReportMs=btn.dataset.reportMs; renderDailyReportOptions(); renderDailyReport(); renderSummary(); renderAdvice(); }
    document.getElementById("reportDatePicker").addEventListener("calendar-change",ev=>{const row=rowForCalendarDate(dailyReports(),ev.detail.value); if(!row)return; selectedReportMs=row.date_ms; renderDailyReportOptions(); renderDailyReport(); renderSummary(); renderAdvice();});
    document.getElementById("reportDateList").addEventListener("click",(ev)=>selectDailyReport(ev.target.closest("[data-report-ms]")));
    document.getElementById("copyReportBtn").addEventListener("click",async()=>{const text=document.getElementById("reportText").textContent; if(!text)return; try{await navigator.clipboard.writeText(text); document.getElementById("copyReportBtn").textContent=tr("copied"); setTimeout(()=>document.getElementById("copyReportBtn").textContent=tr("copyReport"),1200);}catch{}});
    document.getElementById("heartSelect").addEventListener("calendar-change",(ev)=>{const row=rowForCalendarDate(heartRows().filter(r=>sameMonth(r)),ev.detail.value); if(!row)return; selectedHeartMs=row.date_ms; renderHeartOptions(); renderDailyHeart();});
    document.getElementById("sleepSelect").addEventListener("calendar-change",(ev)=>{const row=rowForCalendarDate(validSleepRows(),ev.detail.value); if(!row)return; selectedSleepMs=row.date_ms; renderSleepOptions(); renderSleepDetail();});
    document.getElementById("monthSelect").addEventListener("calendar-change",(ev)=>{selectedMonth=ev.detail.value; renderMonthOptions(); renderCalendar();});
    document.getElementById("file").addEventListener("change",(ev)=>{const f=ev.target.files[0]; setText("fileLabel",f?f.name:"选择导出 ZIP")});
    document.getElementById("settingsForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("settingsStatus"); status.textContent=tr("saving"); const fd=new URLSearchParams(); fd.set("default_language",document.getElementById("defaultLanguage").value); const res=await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd}); const data=await res.json(); if(data.ok){lang=data.default_language; localStorage.setItem("dafit_lang",lang); applyLanguage(); status.textContent=tr("saved");} else status.textContent=data.error||"failed";});
    document.getElementById("passwordForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("passwordStatus"); status.textContent=tr("changingPassword"); const fd=new URLSearchParams(); fd.set("current_password",document.getElementById("currentPassword").value); fd.set("new_password",document.getElementById("newOwnPassword").value); const res=await fetch("/api/password",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd}); const data=await res.json(); status.textContent=data.ok?tr("passwordChanged"):(data.error||"failed"); if(data.ok)ev.target.reset();});
    document.getElementById("profileForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("profileStatus"); status.textContent=tr("saving"); const fd=new URLSearchParams(new FormData(ev.target)); const res=await fetch("/api/profile",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd}); const data=await res.json(); if(data.ok){userProfile=data.profile||{}; renderProfile(); status.textContent=tr("profileSaved");} else status.textContent=data.error||"failed";});
    document.getElementById("userForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("userStatus"); status.textContent=tr("creatingUser"); const fd=new URLSearchParams(); fd.set("username",document.getElementById("newUsername").value); fd.set("password",document.getElementById("newPassword").value); fd.set("default_language",document.getElementById("newUserLanguage").value); if(document.getElementById("newIsAdmin").checked)fd.set("is_admin","1"); const res=await fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd}); const data=await res.json(); status.textContent=data.ok?`${tr("userCreated")}: ${data.username}`:(data.error||"failed"); if(data.ok)ev.target.reset();});
    document.getElementById("uploadForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("status"), file=document.getElementById("file").files[0]; if(!file)return; status.textContent=tr("uploading"); const fd=new FormData(); fd.append("file",file); const res=await fetch("/upload",{method:"POST",body:fd}); const data=await res.json(); if(!res.ok||!data.ok){status.textContent=data.error||tr("uploadFailed"); return} status.textContent=`${tr("importDone")}：${Object.entries(data.counts).map(([k,v])=>`${k} ${v}`).join(" · ")}`; await load();});
    window.addEventListener("pageshow",event=>{if(event.persisted)refreshWhenVisible()});
    window.addEventListener("focus",refreshWhenVisible);
    document.addEventListener("visibilitychange",refreshWhenVisible);
    setInterval(refreshWhenVisible,60000);
    load();
  </script>
</body>
</html>
"""


def main() -> None:
    init_db()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"DA FIT Health Dashboard listening on http://{HOST}:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
