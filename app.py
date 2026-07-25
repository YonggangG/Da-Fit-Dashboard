from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import zipfile
from datetime import datetime, timezone
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
            ("daily_health", "display_date_ms"),
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
        if not should_apply(row["DISPLAY_DATE"]):
            counts["daily_health_entity_skipped"] = counts.get("daily_health_entity_skipped", 0) + 1
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

    for table in ["blood_oxygen", "weight", "water", "goals_setting"]:
        for idx, row in enumerate(payload.get(table) or []):
            if not isinstance(row, dict):
                continue
            date_ms = row.get("DATE")
            if not isinstance(date_ms, int):
                if latest_existing_day:
                    counts[f"{table}_skipped"] = counts.get(f"{table}_skipped", 0) + 1
                    continue
                date_ms = import_id * 1_000_000 + idx
            if isinstance(row.get("DATE"), int) and not should_apply(date_ms):
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
        summary: dict[str, Any] = {
            "latest": {
                "sport": latest(db, "sport"),
                "heart_rate": latest(db, "heart_rate"),
                "sleep": latest_where(db, "sleep", "coalesce(deep,0) + coalesce(shallow,0) + coalesce(rem,0) >= 120"),
                "timing_stress": latest_where(db, "timing_stress", "coalesce(average,0) > 0"),
                "daily_health": latest(db, "daily_health"),
            },
            "series": {
                "sport": rows(db, "select date_ms, date_iso, steps, distance, calories from sport order by date_ms desc limit 1000")[::-1],
                "heart_rate": rows(db, "select date_ms, date_iso, average, min_rate, max_rate from heart_rate where average is not null order by date_ms desc limit 1000")[::-1],
                "sleep": rows(db, "select date_ms, date_iso, deep, shallow, rem, sober, completion, detail_json from sleep order by date_ms desc limit 1000")[::-1],
                "stress": rows(db, "select date_ms, date_iso, average, min_stress, max_stress from timing_stress where average is not null order by date_ms desc limit 1000")[::-1],
                "daily_health": rows(db, "select display_date_ms as date_ms, display_date_iso as date_iso, steps, calories, activity, total_score, grade, raw_json from daily_health order by display_date_ms desc limit 1000")[::-1],
            },
            "imports": rows(db, "select id, filename, export_ms, uploaded_at, counts_json from imports order by id desc limit 1"),
        }
        summary["advice"] = advice(summary)
        return summary


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
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_text(self, value: str, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        payload = value.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_HEAD(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            payload = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
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
    .imports { margin-top:14px; padding:18px; }
    .detail-grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-top:14px; }
    .sleep-detail,.calendar-panel { padding:18px; }
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
    .stage-legend { display:flex; gap:10px; flex-wrap:wrap; margin-top:10px; color:var(--muted); font-size:.82rem; }
    .stage-legend span { display:inline-flex; align-items:center; gap:6px; }
    .calendar-head { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:14px; }
    .calendar-month { margin-top:16px; }
    .calendar-title { font-size:1.25rem; font-weight:900; margin-bottom:10px; }
    .weekdays,.calendar-days { display:grid; grid-template-columns:repeat(7,1fr); gap:10px; }
    .weekdays { color:var(--soft); font-size:.78rem; font-weight:850; text-align:center; margin-bottom:10px; }
    .day-ring { width:46px; aspect-ratio:1; border-radius:50%; display:grid; place-items:center; margin:auto; color:var(--text); font-weight:820; background:conic-gradient(var(--teal) calc(var(--p)*1%), rgba(34,199,173,.16) 0); position:relative; }
    .day-ring::before { content:""; position:absolute; inset:5px; background:#15191d; border-radius:50%; }
    .day-ring span { position:relative; z-index:1; }
    .day-ring.empty { opacity:.18; }
    .day-ring.today { color:#05251f; background:conic-gradient(var(--teal) calc(var(--p)*1%), rgba(34,199,173,.25) 0); }
    .day-ring.today::before { background:rgba(34,199,173,.7); }
    table { width:100%; border-collapse:collapse; }
    th,td { text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); color:var(--muted); font-size:.9rem; vertical-align:top; }
    th { color:var(--text); font-size:.78rem; text-transform:uppercase; }
    @media (max-width:900px) { .topbar,.grid,.detail-grid,.settings-grid{display:block}.profile-form{grid-template-columns:1fr}.upload,.side,.calendar-panel,.settings-box{margin-top:14px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.sleep-main{grid-template-columns:1fr}.donut-wrap{margin:auto} }
    @media (max-width:560px) { .cards{grid-template-columns:1fr}.value{font-size:1.7rem} }
  </style>
</head>
<body>
  <main class="wrap">
    <div class="topbar">
      <div><h1>DA FIT Health Dashboard</h1><p class="lead" data-i18n="lead">上传 DA FIT 导出文件，本地解析入库，查看步数、心率、睡眠、压力趋势和日常建议。</p></div>
      <section class="panel upload">
        <div class="toolbar"><span id="userBadge">--</span><select id="langSelect" aria-label="Language"><option value="zh">中文</option><option value="en">English</option></select><a class="link-btn" href="/logout" data-i18n="logout">退出</a></div>
        <form id="uploadForm"><label id="fileLabel" class="file-label" for="file" data-i18n="chooseZip">选择导出 ZIP</label><input id="file" name="file" type="file" accept=".zip,.txt,.json" required /><button type="submit" data-i18n="upload">上传处理</button></form><div id="status" class="status"></div>
      </section>
    </div>
    <nav class="page-tabs"><button class="page-tab active" data-page="dashboard" data-i18n="dashboardTab">Dashboard</button><button class="page-tab" data-page="users" data-i18n="usersTab">用户管理</button></nav>
    <section id="dashboardPage" class="page-section">
    <section class="panel month-control"><h2 data-i18n="metricMonth">指标月份</h2><select id="metricMonthSelect" aria-label="选择指标月份"></select></section>
    <section class="cards">
      <div class="panel card"><div class="label" data-i18n="stepsCard">最新步数</div><div id="steps" class="value">--</div><div id="stepsSub" class="sub">等待上传</div></div>
      <div class="panel card"><div class="label" data-i18n="heartCard">平均心率</div><div id="hr" class="value">--</div><div id="hrSub" class="sub">bpm</div></div>
      <div class="panel card"><div class="label" data-i18n="sleepCard">睡眠</div><div id="sleep" class="value">--</div><div id="sleepSub" class="sub">深睡 / 浅睡 / REM</div></div>
      <div class="panel card"><div class="label" data-i18n="stressCard">压力</div><div id="stress" class="value">--</div><div id="stressSub" class="sub">平均值</div></div>
    </section>
    <section class="grid">
      <div class="panel chart"><div class="chart-head"><h2 id="chartTitle">步数趋势</h2><div class="tabs"><button class="tab active" data-chart="steps" data-i18n="stepsTab">步数</button><button class="tab" data-chart="heart" data-i18n="heartTab">心率</button><button class="tab" data-chart="sleep" data-i18n="sleepTab">睡眠</button><button class="tab" data-chart="stress" data-i18n="stressTab">压力</button></div></div><svg id="chartSvg" viewBox="0 0 760 240" preserveAspectRatio="none" aria-label="health chart"></svg></div>
      <aside class="panel side"><h2 data-i18n="advice">健康建议</h2><div id="advice" class="advice"></div></aside>
    </section>
    <section class="detail-grid">
      <section class="panel sleep-detail">
        <div class="chart-head"><h2 data-i18n="sleepRatio">睡眠比例</h2><select id="sleepSelect" aria-label="选择睡眠日期"></select></div>
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
      </section>
      <section class="panel calendar-panel">
        <div class="calendar-head"><h2 data-i18n="monthlyRings">月度活动环</h2><select id="monthSelect" aria-label="选择月份"></select></div>
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
    let state=null,userProfile={},currentChart="steps",selectedSleepMs=null,selectedMonth=null,selectedMetricMonth=null,lang=localStorage.getItem("dafit_lang")||"zh"; const fmt=new Intl.NumberFormat(); const dt=(iso)=>iso?new Date(iso).toLocaleDateString():"--"; const num=(v,d=0)=>Number.isFinite(Number(v))?Number(v).toFixed(d):"--"; const sum=(arr)=>arr.reduce((a,b)=>a+Number(b||0),0); const setText=(id,text)=>document.getElementById(id).textContent=text;
    const I18N={zh:{lead:"上传 DA FIT 导出文件，本地解析入库，查看步数、心率、睡眠、压力趋势和日常建议。",dashboardTab:"Dashboard",usersTab:"用户管理",logout:"退出",chooseZip:"选择导出 ZIP",upload:"上传处理",addUser:"增加账户",metricMonth:"指标月份",stepsCard:"最新步数",heartCard:"平均心率",sleepCard:"睡眠",stressCard:"压力",advice:"健康建议",stepsTab:"步数",heartTab:"心率",sleepTab:"睡眠",stressTab:"压力",sleepRatio:"睡眠比例",sleepQuality:"睡眠质量分",poor:"差",secondary:"一般",good:"好",excellent:"优秀",sleepStage:"睡眠阶段曲线",monthlyRings:"月度活动环",recentImport:"最近导入",file:"文件",importTime:"导入时间",exportTimestamp:"导出时间戳",tableCounts:"表计数",profileSettings:"个人设置",defaultLanguage:"默认语言",saveSettings:"保存设置",changePassword:"修改密码",currentPassword:"当前密码",newPassword:"新密码",newUsername:"新用户名",adminRole:"管理员",stepsTrend:"步数趋势",heartTrend:"平均心率趋势",sleepTrend:"睡眠时长趋势",stressTrend:"压力趋势",noSteps:"无步数数据",noHeart:"无心率数据",noSleep:"无睡眠数据",noStress:"无压力数据",goodSteps:"活动量不错",midSteps:"步数中等",lowSteps:"活动量偏低",goodSleep:"睡眠时长充足",lowSleep:"睡眠时长不足",highHeart:"平均心率偏高",lowHeart:"平均心率偏低",okHeart:"心率区间平稳",highStress:"压力指数偏高",waiting:"等待更多数据",noSleepStage:"这一天没有睡眠阶段时间线",noValidSleep:"暂无有效睡眠明细",noSleepData:"暂无睡眠数据",noMonthData:"暂无月份数据",noChartData:"没有该指标数据",noCalendar:"上传有历史记录的导出文件后显示月度活动环",uploading:"上传并解析中...",uploadFailed:"上传失败",importDone:"导入完成",creatingUser:"正在增加账户...",userCreated:"账户已增加",saving:"正在保存...",saved:"设置已保存",changingPassword:"正在修改密码...",passwordChanged:"密码已修改",healthProfile:"健康个人资料",heightCm:"身高 cm",weightKg:"体重 kg",gender:"性别",unknown:"未知",male:"男",female:"女",birthday:"生日",birthYear:"出生年份",stepLengthCm:"步长 cm",dailyStepsGoal:"每日步数目标",dailyCaloriesGoal:"每日卡路里目标",dailyMinutesGoal:"每日运动分钟目标",deviceName:"设备名称",saveProfile:"保存个人资料",profileSaved:"个人资料已保存",autoProfileHint:"上传 DA FIT ZIP 后会自动更新这些资料；也可以在这里手动修改。"},en:{lead:"Upload DA FIT exports, parse them locally, and review steps, heart rate, sleep, stress trends, and daily suggestions.",dashboardTab:"Dashboard",usersTab:"User management",logout:"Logout",chooseZip:"Choose export ZIP",upload:"Upload",addUser:"Add user",metricMonth:"Metric month",stepsCard:"Latest steps",heartCard:"Average heart rate",sleepCard:"Sleep",stressCard:"Stress",advice:"Health advice",stepsTab:"Steps",heartTab:"Heart rate",sleepTab:"Sleep",stressTab:"Stress",sleepRatio:"Sleep ratio",sleepQuality:"Sleep Quality Score",poor:"Poor",secondary:"Secondary",good:"Good",excellent:"Excellent",sleepStage:"Sleep stage chart",monthlyRings:"Monthly activity rings",recentImport:"Latest import",file:"File",importTime:"Import time",exportTimestamp:"Export timestamp",tableCounts:"Table counts",profileSettings:"Profile settings",defaultLanguage:"Default language",saveSettings:"Save settings",changePassword:"Change password",currentPassword:"Current password",newPassword:"New password",newUsername:"New username",adminRole:"Admin",stepsTrend:"Steps trend",heartTrend:"Average heart rate trend",sleepTrend:"Sleep duration trend",stressTrend:"Stress trend",noSteps:"no steps data",noHeart:"no heart-rate data",noSleep:"no sleep data",noStress:"no stress data",goodSteps:"Good activity",midSteps:"Moderate steps",lowSteps:"Low activity",goodSleep:"Enough sleep",lowSleep:"Short sleep",highHeart:"Average heart rate is high",lowHeart:"Average heart rate is low",okHeart:"Heart rate looks steady",highStress:"Stress is elevated",waiting:"Waiting for more data",noSleepStage:"No sleep-stage timeline for this date",noValidSleep:"No valid sleep detail",noSleepData:"No sleep data",noMonthData:"No month data",noChartData:"No data for this metric",noCalendar:"Upload an export with history to show monthly activity rings",uploading:"Uploading and parsing...",uploadFailed:"Upload failed",importDone:"Import complete",creatingUser:"Creating user...",userCreated:"User created",saving:"Saving...",saved:"Settings saved",changingPassword:"Changing password...",passwordChanged:"Password changed",healthProfile:"Health profile",heightCm:"Height cm",weightKg:"Weight kg",gender:"Gender",unknown:"Unknown",male:"Male",female:"Female",birthday:"Birthday",birthYear:"Birth year",stepLengthCm:"Step length cm",dailyStepsGoal:"Daily steps goal",dailyCaloriesGoal:"Daily calories goal",dailyMinutesGoal:"Daily activity minutes goal",deviceName:"Device name",saveProfile:"Save health profile",profileSaved:"Health profile saved",autoProfileHint:"Uploading a DA FIT ZIP updates these fields automatically. You can also edit them here."}};
    const tr=(key)=>I18N[lang]?.[key]||I18N.zh[key]||key;
    function applyLanguage(){document.documentElement.lang=lang==="en"?"en":"zh-CN"; document.getElementById("langSelect").value=lang; document.querySelectorAll("[data-i18n]").forEach(n=>n.textContent=tr(n.dataset.i18n)); document.querySelectorAll("[data-placeholder-key]").forEach(n=>n.placeholder=tr(n.dataset.placeholderKey)); renderSummary(); renderAdvice(); renderChart(); renderSleepOptions(); renderSleepDetail(); renderCalendar();}
    async function initUser(){ const me=await fetch("/api/me").then(r=>r.ok?r.json():null); if(!me){location.href="/login";return} if(!localStorage.getItem("dafit_lang"))lang=me.default_language||"zh"; userProfile=me.profile||{}; setText("userBadge",me.username); document.getElementById("defaultLanguage").value=me.default_language||"zh"; document.getElementById("adminPanel").style.display=me.is_admin?"block":"none"; renderProfile(); }
    async function load(){ await initUser(); state=await fetch("/api/summary").then(r=>r.json()); renderMonthOptions(); renderSummary(); renderAdvice(); renderImports(); renderChart(); renderSleepOptions(); renderSleepDetail(); renderCalendar(); applyLanguage(); }
    function dateInputFromMs(ms){ if(!ms)return""; const d=new Date(Number(ms)); return Number.isNaN(d.getTime())?"":d.toISOString().slice(0,10); }
    function setInput(id,value){ document.getElementById(id).value=value??""; }
    function renderProfile(){ const p=userProfile||{}; setInput("profileHeightCm",p.height_cm); setInput("profileWeightKg",p.weight_kg); setInput("profileGender",p.gender); setInput("profileBirthday",dateInputFromMs(p.birthday_ms)); setInput("profileBirthYear",p.birth_year); setInput("profileStepLengthCm",p.step_length_cm); setInput("profileDailyStepsGoal",p.daily_steps_goal); setInput("profileDailyCaloriesGoal",p.daily_calories_goal); setInput("profileDailyMinutesGoal",p.daily_minutes_goal); setInput("profileDeviceName",p.device_name); }
    function sameMonth(row,month=selectedMetricMonth){ return row?.date_iso&&monthKey(new Date(row.date_iso))===month; }
    function latestInMonth(rows,month=selectedMetricMonth,predicate=()=>true){ return (rows||[]).filter(r=>sameMonth(r,month)&&predicate(r)).at(-1); }
    function monthRows(){ const s=state.series||{}; return {sport:latestInMonth(s.sport), daily:latestInMonth(s.daily_health), heart:latestInMonth(s.heart_rate,selectedMetricMonth,r=>Number(r.average)>0), sleep:latestInMonth(s.sleep,selectedMetricMonth,r=>sum([r.deep,r.shallow,r.rem])>0), stress:latestInMonth(s.stress,selectedMetricMonth,r=>Number(r.average)>0)}; }
    function renderSummary(){ const {sport,daily,heart,sleep,stress}=monthRows(); for(const id of ["steps","hr","sleep","stress"])setText(id,"--"); setText("stepsSub",`${selectedMetricMonth||"--"} ${tr("noSteps")}`); setText("hrSub",`${selectedMetricMonth||"--"} ${tr("noHeart")}`); setText("sleepSub",`${selectedMetricMonth||"--"} ${tr("noSleep")}`); setText("stressSub",`${selectedMetricMonth||"--"} ${tr("noStress")}`); const stepsRow=sport||daily; if(stepsRow){const steps=Number(sport?.steps ?? daily?.steps ?? 0); const calories=Number(sport?.calories ?? daily?.calories ?? 0); const distance=Number(sport?.distance ?? 0); const dailySteps=daily&&sport&&Number(daily.steps)!==steps?` · Daily Health ${fmt.format(Number(daily.steps||0))}`:""; setText("steps",fmt.format(steps)); setText("stepsSub",`${dt(sport?.date_iso||daily?.date_iso)} · ${distance?num(distance,0)+" m · ":""}${num(calories,0)} kcal · Steps${dailySteps}`)} if(heart){setText("hr",num(heart.average,0)); setText("hrSub",`${dt(heart.date_iso)} · ${num(heart.min_rate,0)}-${num(heart.max_rate,0)} bpm`)} if(sleep){const total=sum([sleep.deep,sleep.shallow,sleep.rem]); setText("sleep",total?`${(total/60).toFixed(1)}h`:"--"); setText("sleepSub",lang==="en"?`${dt(sleep.date_iso)} · Deep ${num(sleep.deep,0)} / Light ${num(sleep.shallow,0)} / REM ${num(sleep.rem,0)} min`:`${dt(sleep.date_iso)} · 深 ${num(sleep.deep,0)} / 浅 ${num(sleep.shallow,0)} / REM ${num(sleep.rem,0)} 分`)} if(stress){setText("stress",num(stress.average,0)); setText("stressSub",`${dt(stress.date_iso)} · ${num(stress.min_stress,0)}-${num(stress.max_stress,0)}`)}}
    function renderAdvice(){ const {sport,daily,heart,sleep,stress}=monthRows(); const items=[]; const add=(level,title,text)=>items.push({level,title,text}); const steps=Number(sport?.steps ?? daily?.steps ?? 0); if(steps){ if(steps>=8000)add("good",tr("goodSteps"),lang==="en"?`${fmt.format(steps)} steps in ${selectedMetricMonth}; this is near or above a common daily activity target.`:`${selectedMetricMonth} 最新记录 ${fmt.format(steps)} 步，已经接近或超过常见日常活动目标。`); else if(steps>=4000)add("watch",tr("midSteps"),lang==="en"?`${fmt.format(steps)} steps in ${selectedMetricMonth}; a walk can help bring the day closer to 7,000-8,000 steps.`:`${selectedMetricMonth} 最新记录 ${fmt.format(steps)} 步，可以用饭后散步把当天活动量补到 7000-8000 步区间。`); else add("warn",tr("lowSteps"),lang==="en"?`${fmt.format(steps)} steps in ${selectedMetricMonth}; consider 20-30 minutes of easy walking if you feel well.`:`${selectedMetricMonth} 最新记录 ${fmt.format(steps)} 步，建议安排 20-30 分钟轻中度步行。`);} if(sleep){const total=sum([sleep.deep,sleep.shallow,sleep.rem]); if(total>=420)add("good",tr("goodSleep"),lang==="en"?`Latest sleep in ${selectedMetricMonth} is about ${(total/60).toFixed(1)} hours.`:`${selectedMetricMonth} 最近睡眠约 ${(total/60).toFixed(1)} 小时。继续保持固定作息。`); else if(total>0)add("watch",tr("lowSleep"),lang==="en"?`Latest sleep in ${selectedMetricMonth} is about ${(total/60).toFixed(1)} hours; protect a continuous sleep window.`:`${selectedMetricMonth} 最近睡眠约 ${(total/60).toFixed(1)} 小时，优先保证连续睡眠窗口。`);} if(heart?.average){const avg=Number(heart.average); if(avg>=95)add("watch",tr("highHeart"),lang==="en"?`Latest monthly reading is about ${avg.toFixed(0)} bpm; interpret with activity, caffeine, stress, and sleep.`:`${selectedMetricMonth} 最新平均心率约 ${avg.toFixed(0)} bpm。结合运动、咖啡因、压力和睡眠一起看。`); else if(avg<=55)add("watch",tr("lowHeart"),lang==="en"?`Latest monthly reading is about ${avg.toFixed(0)} bpm. If symptoms occur, consult a clinician.`:`${selectedMetricMonth} 最新平均心率约 ${avg.toFixed(0)} bpm。如果伴随不适，应线下咨询医生。`); else add("good",tr("okHeart"),lang==="en"?`Latest monthly reading is about ${avg.toFixed(0)} bpm.`:`${selectedMetricMonth} 最新平均心率约 ${avg.toFixed(0)} bpm。`);} if(stress?.average&&Number(stress.average)>=60)add("watch",tr("highStress"),lang==="en"?`Latest stress average is about ${Number(stress.average).toFixed(0)}; short breaks or easy walking may help.`:`${selectedMetricMonth} 最近压力均值约 ${Number(stress.average).toFixed(0)}，可以安排短休息、呼吸练习或低强度散步。`); if(!items.length)add("watch",tr("waiting"),lang==="en"?`No usable records for ${selectedMetricMonth}. Upload a DA FIT export with this month to generate advice.`:`${selectedMetricMonth} 没有足够数据。上传包含该月记录的 DA FIT 导出后，这里会生成建议。`); document.getElementById("advice").innerHTML=items.map(item=>`<div class="advice-item ${item.level}"><div class="advice-title">${escapeHtml(item.title)}</div><div class="advice-text">${escapeHtml(item.text)}</div></div>`).join(""); }
    function renderImports(){ document.getElementById("imports").innerHTML=(state.imports||[]).map(row=>{let counts=row.counts_json; try{counts=Object.entries(JSON.parse(counts)).map(([k,v])=>`${k}:${v}`).join(" · ")}catch{} const exportAt=row.export_ms?new Date(row.export_ms).toLocaleString():"--"; return `<tr><td>${escapeHtml(row.filename)}</td><td>${new Date(row.uploaded_at).toLocaleString()}</td><td>${exportAt}</td><td>${escapeHtml(counts)}</td></tr>`}).join(""); }
    function fmtMinutes(minutes){minutes=Number(minutes||0); const h=Math.floor(minutes/60), m=Math.round(minutes%60); return h?`${h} H ${m} M`:`${m} M`;}
    function dailyRaw(){ const row=state.latest?.daily_health; if(!row?.raw_json)return{}; try{return JSON.parse(row.raw_json)}catch{return{}} }
    function sleepQuality(){ const raw=dailyRaw(); if(Number(raw.SLEEP_QUALITY_HAS_DATA||0)!==1)return null; const score=Number(raw.SLEEP_QUALITY_VALUE||raw.SLEEP_QUALITY_SCORE||0); return Number.isFinite(score)?Math.max(0,Math.min(100,score)):null; }
    function validSleepRows(){ return (state.series?.sleep||[]).filter(r=>sum([r.deep,r.shallow,r.rem])>0); }
    function renderSleepOptions(){ const rows=validSleepRows(); const sel=document.getElementById("sleepSelect"); if(!rows.length){sel.innerHTML=`<option>${tr("noSleepData")}</option>`; selectedSleepMs=null; return} const summarySleep=state.latest?.sleep; if(!selectedSleepMs||!rows.some(r=>String(r.date_ms)===String(selectedSleepMs)))selectedSleepMs=(summarySleep&&rows.some(r=>String(r.date_ms)===String(summarySleep.date_ms)))?summarySleep.date_ms:rows[rows.length-1].date_ms; sel.innerHTML=rows.slice().reverse().map(r=>`<option value="${r.date_ms}" ${String(r.date_ms)===String(selectedSleepMs)?"selected":""}>${dt(r.date_iso)} · ${fmtMinutes(sum([r.deep,r.shallow,r.rem]))}</option>`).join(""); }
    function selectedSleep(){ return validSleepRows().find(r=>String(r.date_ms)===String(selectedSleepMs)) || validSleepRows().at(-1); }
    function parseSleepDetail(raw){ if(!raw)return[]; try{let v=JSON.parse(raw); if(typeof v==="string")v=JSON.parse(v); if(Array.isArray(v))return v; if(Array.isArray(v.detail))return v.detail;}catch{} return[]; }
    function renderSleepStage(sleep){ const svg=document.getElementById("sleepStageSvg"), detail=parseSleepDetail(sleep?.detail_json); const colors={0:"var(--orange)",1:"var(--magenta)",2:"var(--violet)",3:"var(--coral)"}, labels={0:"Awake",1:"Light",2:"Deep",3:"REM"}, yByType={0:22,3:52,1:82,2:112}; if(!detail.length){svg.innerHTML=`<text x="380" y="76" text-anchor="middle" class="tick">${tr("noSleepStage")}</text>`; return} const W=760,H=150,P=34, total=sum(detail.map(d=>d.total)); let used=0; const rows=[0,3,1,2].map(t=>`<text class="tick" x="2" y="${yByType[t]+13}">${labels[t]}</text><line class="axis" x1="${P}" y1="${yByType[t]+9}" x2="${W-P}" y2="${yByType[t]+9}"/>`).join(""); const blocks=detail.map(d=>{const w=Math.max(2,Number(d.total||0)/Math.max(1,total)*(W-P*2)), x=P+used/Math.max(1,total)*(W-P*2), y=yByType[d.type]??82; used+=Number(d.total||0); const label=`${labels[d.type]||"Stage"} ${d.start||""}-${d.end||""} · ${fmtMinutes(d.total)}`; return `<rect class="stage-block" x="${x}" y="${y}" width="${w}" height="18" fill="${colors[d.type]||"var(--blue)"}"><title>${escapeHtml(label)}</title></rect>`;}).join(""); const first=detail[0], last=detail[detail.length-1]; svg.innerHTML=`${rows}${blocks}<text class="tick" x="${P}" y="${H-6}">${escapeHtml(first.start||"")}</text><text class="tick" x="${W-P-36}" y="${H-6}">${escapeHtml(last.end||"")}</text>`; }
    function renderSleepDetail(){ const sleep=selectedSleep(); const colors={deep:"var(--violet)",shallow:"var(--magenta)",rem:"var(--coral)",sober:"var(--orange)"}, labels={deep:"Deep Sleep",shallow:"Light Sleep",rem:"Rapid Eye Movement",sober:"Awake"}; const parts=[["deep",labels.deep,sleep?.deep],["shallow",labels.shallow,sleep?.shallow],["rem",labels.rem,sleep?.rem],["sober",labels.sober,sleep?.sober]].map(([key,label,value])=>({key,label,value:Number(value||0)})); const total=sum(parts.filter(p=>p.key!=="sober").map(p=>p.value)); setText("sleepDate",sleep?.date_iso?dt(sleep.date_iso):"--"); setText("sleepTotal",total?fmtMinutes(total):"--"); document.getElementById("sleepRatioRows").innerHTML=parts.filter(p=>p.value>0||p.key!=="sober").map(p=>`<div class="ratio-row"><div class="ratio-label"><span class="dot" style="background:${colors[p.key]}"></span>${p.label}</div><strong>${fmtMinutes(p.value)}</strong></div>`).join("") || `<div class="sub">${tr("noValidSleep")}</div>`; const svg=document.getElementById("sleepDonut"); if(!total){svg.innerHTML=`<circle cx="85" cy="85" r="58" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="22"/>`} else {let used=0,circ=2*Math.PI*58; svg.innerHTML=parts.filter(p=>p.key!=="sober"&&p.value>0).map(p=>{const len=p.value/total*circ, off=-(used/circ)*circ; used+=len; return `<circle cx="85" cy="85" r="58" fill="none" stroke="${colors[p.key]}" stroke-width="22" stroke-dasharray="${len} ${circ-len}" stroke-dashoffset="${off}" transform="rotate(-90 85 85)" stroke-linecap="butt"><title>${escapeHtml(p.label)} · ${fmtMinutes(p.value)}</title></circle>`}).join("");} const q=sleepQuality(); setText("qualityScore",q==null?"--":Math.round(q)); document.getElementById("qualityMarker").style.left=`${q==null?0:q}%`; renderSleepStage(sleep); }
    function activityDays(){ const rows=[...(state.series?.daily_health||[]),...(state.series?.sport||[])]; const byDay=new Map(); for(const r of rows){const iso=r.date_iso; if(!iso)continue; const d=new Date(iso), key=d.toISOString().slice(0,10); const steps=Number(r.steps||0), goal=Number(dailyRaw().STEPS_GOAL||10000); const p=Math.max(0,Math.min(100,(steps/goal)*100)); const prev=byDay.get(key); if(!prev||p>prev.p)byDay.set(key,{date:d,steps,p});} return [...byDay.values()].sort((a,b)=>a.date-b.date); }
    function monthKey(d){ return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}`; }
    function allMonths(){ const s=state.series||{}, months=new Set(); for(const rows of [s.sport,s.heart_rate,s.sleep,s.stress,s.daily_health]) for(const r of rows||[]) if(r.date_iso)months.add(monthKey(new Date(r.date_iso))); return [...months].sort(); }
    function renderMonthOptions(){ const months=allMonths(), metricSel=document.getElementById("metricMonthSelect"), ringSel=document.getElementById("monthSelect"); if(!months.length){metricSel.innerHTML=ringSel.innerHTML=`<option>${tr("noMonthData")}</option>`; selectedMetricMonth=selectedMonth=null; return} if(!selectedMetricMonth||!months.includes(selectedMetricMonth))selectedMetricMonth=months[months.length-1]; if(!selectedMonth||!months.includes(selectedMonth))selectedMonth=selectedMetricMonth; const html=(selected)=>months.map(m=>`<option value="${m}" ${m===selected?"selected":""}>${m}</option>`).join(""); metricSel.innerHTML=html(selectedMetricMonth); ringSel.innerHTML=html(selectedMonth); }
    function renderCalendar(){ const days=activityDays().filter(d=>monthKey(d.date)===selectedMonth); const monthNames=lang==="en"?["January","February","March","April","May","June","July","August","September","October","November","December"]:["一月","二月","三月","四月","五月","六月","七月","八月","九月","十月","十一月","十二月"]; if(!days.length){document.getElementById("calendarMonths").innerHTML=`<div class="sub">${tr("noCalendar")}</div>`; return} const [year,month]=selectedMonth.split("-").map(Number), first=new Date(year,month-1,1), last=new Date(year,month,0).getDate(), map=new Map(days.map(v=>[v.date.getDate(),v])); let cells=""; for(let i=0;i<first.getDay();i++)cells+=`<div></div>`; for(let day=1;day<=last;day++){const v=map.get(day), today=new Date().toDateString()===new Date(year,month-1,day).toDateString(), title=v?`${selectedMonth}-${String(day).padStart(2,"0")} · ${fmt.format(v.steps)} steps · ${Math.round(v.p)}%`:"No data"; cells+=`<div class="day-ring ${v?"":"empty"} ${today?"today":""}" style="--p:${v?.p||0}" title="${escapeHtml(title)}"><span>${day}</span></div>`;} document.getElementById("calendarMonths").innerHTML=`<div class="calendar-month"><div class="calendar-title">${monthNames[month-1]} ${year}</div><div class="calendar-days">${cells}</div></div>`; }
    function chartData(){ const s=state.series||{}; if(currentChart==="steps")return{title:`${selectedMetricMonth} ${tr("stepsTrend")}`,unit:"steps",mode:"bar",rows:s.sport||[],y:r=>r.steps,valid:v=>v>=0,fmt:v=>fmt.format(Math.round(v))}; if(currentChart==="heart")return{title:`${selectedMetricMonth} ${tr("heartTrend")}`,unit:"bpm",mode:"line",rows:s.heart_rate||[],y:r=>r.average,valid:v=>v>0,fmt:v=>`${Math.round(v)} bpm`}; if(currentChart==="sleep")return{title:`${selectedMetricMonth} ${tr("sleepTrend")}`,unit:"h",mode:"bar",rows:s.sleep||[],y:r=>sum([r.deep,r.shallow,r.rem])/60,valid:v=>v>0,fmt:v=>`${v.toFixed(1)} h`}; return{title:`${selectedMetricMonth} ${tr("stressTrend")}`,unit:"",mode:"line",rows:s.stress||[],y:r=>r.average,valid:v=>v>0,fmt:v=>String(Math.round(v))};}
    function renderChart(){ const cfg=chartData(); setText("chartTitle",cfg.title); const svg=document.getElementById("chartSvg"); const rows=cfg.rows.filter(r=>{const v=Number(cfg.y(r)); return sameMonth(r)&&Number.isFinite(v)&&cfg.valid(v);}); if(!rows.length){svg.innerHTML=`<text x="380" y="120" text-anchor="middle" class="tick">${selectedMetricMonth||""} ${tr("noChartData")}</text>`; return} const W=760,H=240,P=26, vals=rows.map(cfg.y).map(Number), min=Math.min(0,...vals), max=Math.max(...vals)||1, x=i=>P+i*((W-P*2)/Math.max(1,rows.length-1)), y=v=>H-P-((v-min)/Math.max(1,max-min))*(H-P*2); const grid=[0,.25,.5,.75,1].map(t=>{const yy=P+t*(H-P*2), val=max-t*(max-min); return `<line class="axis" x1="${P}" y1="${yy}" x2="${W-P}" y2="${yy}"/><text class="tick" x="4" y="${yy+4}">${Math.round(val)}</text>`}).join(""); let shapes=""; if(cfg.mode==="bar"){const bw=Math.max(2,(W-P*2)/rows.length*.72); shapes=rows.map((r,i)=>{const v=Number(cfg.y(r)), label=`${dt(r.date_iso)} · ${cfg.fmt(v)}`; return `<rect class="bar" x="${x(i)-bw/2}" y="${y(v)}" width="${bw}" height="${H-P-y(v)}"><title>${escapeHtml(label)}</title></rect>`}).join("")} else {const points=rows.map((r,i)=>`${x(i)},${y(cfg.y(r))}`).join(" "), area=`${P},${H-P} ${points} ${x(rows.length-1)},${H-P}`, dots=rows.map((r,i)=>{const v=Number(cfg.y(r)), label=`${dt(r.date_iso)} · ${cfg.fmt(v)}`; return `<circle class="point" cx="${x(i)}" cy="${y(v)}" r="3.5"><title>${escapeHtml(label)}</title></circle><circle class="point-hit" cx="${x(i)}" cy="${y(v)}" r="10"><title>${escapeHtml(label)}</title></circle>`}).join(""); shapes=`<polygon class="area" points="${area}"></polygon><polyline class="line" points="${points}"></polyline>${dots}`} const first=rows[0], last=rows[rows.length-1]; svg.innerHTML=`${grid}${shapes}<text class="tick" x="${P}" y="${H-4}">${dt(first.date_iso)}</text><text class="tick" x="${W-P-70}" y="${H-4}">${dt(last.date_iso)}</text>`; }
    function escapeHtml(s){return String(s??"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
    document.querySelectorAll(".page-tab").forEach(btn=>btn.addEventListener("click",()=>{document.querySelectorAll(".page-tab").forEach(b=>b.classList.remove("active")); btn.classList.add("active"); document.getElementById("dashboardPage").classList.toggle("hidden",btn.dataset.page!=="dashboard"); document.getElementById("usersPage").classList.toggle("hidden",btn.dataset.page!=="users");}));
    document.querySelectorAll(".tab").forEach(btn=>btn.addEventListener("click",()=>{document.querySelectorAll(".tab").forEach(b=>b.classList.remove("active")); btn.classList.add("active"); currentChart=btn.dataset.chart; renderChart()}));
    document.getElementById("langSelect").addEventListener("change",(ev)=>{lang=ev.target.value; localStorage.setItem("dafit_lang",lang); applyLanguage();});
    document.getElementById("metricMonthSelect").addEventListener("change",(ev)=>{selectedMetricMonth=ev.target.value; renderSummary(); renderAdvice(); renderChart();});
    document.getElementById("sleepSelect").addEventListener("change",(ev)=>{selectedSleepMs=ev.target.value; renderSleepDetail();});
    document.getElementById("monthSelect").addEventListener("change",(ev)=>{selectedMonth=ev.target.value; renderCalendar();});
    document.getElementById("file").addEventListener("change",(ev)=>{const f=ev.target.files[0]; setText("fileLabel",f?f.name:"选择导出 ZIP")});
    document.getElementById("settingsForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("settingsStatus"); status.textContent=tr("saving"); const fd=new URLSearchParams(); fd.set("default_language",document.getElementById("defaultLanguage").value); const res=await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd}); const data=await res.json(); if(data.ok){lang=data.default_language; localStorage.setItem("dafit_lang",lang); applyLanguage(); status.textContent=tr("saved");} else status.textContent=data.error||"failed";});
    document.getElementById("passwordForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("passwordStatus"); status.textContent=tr("changingPassword"); const fd=new URLSearchParams(); fd.set("current_password",document.getElementById("currentPassword").value); fd.set("new_password",document.getElementById("newOwnPassword").value); const res=await fetch("/api/password",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd}); const data=await res.json(); status.textContent=data.ok?tr("passwordChanged"):(data.error||"failed"); if(data.ok)ev.target.reset();});
    document.getElementById("profileForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("profileStatus"); status.textContent=tr("saving"); const fd=new URLSearchParams(new FormData(ev.target)); const res=await fetch("/api/profile",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd}); const data=await res.json(); if(data.ok){userProfile=data.profile||{}; renderProfile(); status.textContent=tr("profileSaved");} else status.textContent=data.error||"failed";});
    document.getElementById("userForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("userStatus"); status.textContent=tr("creatingUser"); const fd=new URLSearchParams(); fd.set("username",document.getElementById("newUsername").value); fd.set("password",document.getElementById("newPassword").value); fd.set("default_language",document.getElementById("newUserLanguage").value); if(document.getElementById("newIsAdmin").checked)fd.set("is_admin","1"); const res=await fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:fd}); const data=await res.json(); status.textContent=data.ok?`${tr("userCreated")}: ${data.username}`:(data.error||"failed"); if(data.ok)ev.target.reset();});
    document.getElementById("uploadForm").addEventListener("submit",async(ev)=>{ev.preventDefault(); const status=document.getElementById("status"), file=document.getElementById("file").files[0]; if(!file)return; status.textContent=tr("uploading"); const fd=new FormData(); fd.append("file",file); const res=await fetch("/upload",{method:"POST",body:fd}); const data=await res.json(); if(!res.ok||!data.ok){status.textContent=data.error||tr("uploadFailed"); return} status.textContent=`${tr("importDone")}：${Object.entries(data.counts).map(([k,v])=>`${k} ${v}`).join(" · ")}`; await load();});
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
