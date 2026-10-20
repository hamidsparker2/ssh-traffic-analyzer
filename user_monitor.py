#!/usr/bin/env python3
import subprocess
import time
import sys
import pwd
import ipaddress
import socket
import re
import json
import signal
import threading
from datetime import datetime, timedelta

# 1. Static CIDR ranges for apps that use raw TCP / custom protocols without SNI
APP_IP_RANGES = {
    "Telegram": [
        "149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22",
        "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
        "91.108.56.0/22", "185.76.151.0/24"
    ],
    "WhatsApp": [
        "185.60.216.0/22"
    ],
    "TikTok": [
        "161.117.0.0/16", "47.246.0.0/16", "139.177.224.0/19"
    ]
}

# 2. Exact SNI / Domain / rDNS keyword mapping (Specific first)
KEYWORDS_MAP = [
    # Telegram
    ("telegram", "Telegram"),
    ("t.me", "Telegram"),
    ("telesco.pe", "Telegram"),

    # AI Apps (ChatGPT & Gemini & Claude)
    ("chatgpt.com", "ChatGPT (OpenAI)"),
    ("openai.com", "ChatGPT (OpenAI)"),
    ("oaistatic.com", "ChatGPT (OpenAI)"),
    ("oaiusercontent.com", "ChatGPT (OpenAI)"),
    ("gemini.google", "Google Gemini"),
    ("bard.google", "Google Gemini"),
    ("generativelanguage.googleapis", "Google Gemini"),
    ("robinfrontend-pa.googleapis", "Google Gemini (Mobile App)"),
    ("proactivebackend-pa.googleapis", "Google Gemini (Mobile App)"),
    ("alkalimakersuite-pa", "Google Gemini"),
    ("aistudio.google", "Google Gemini"),
    ("claude.ai", "Claude AI"),
    ("anthropic.com", "Claude AI"),

    # Social Media & Messaging
    ("instagram", "Instagram"),
    ("cdninstagram", "Instagram"),
    ("whatsapp", "WhatsApp"),
    ("wa.me", "WhatsApp"),
    ("tiktok", "TikTok"),
    ("byteoversea", "TikTok"),
    ("ibytedtos", "TikTok"),
    ("ibyteimg", "TikTok"),
    ("musical.ly", "TikTok"),
    ("snssdk.com", "TikTok"),
    ("facebook", "Facebook"),
    ("fbcdn.net", "Meta (Instagram / Facebook)"),
    ("fbsbx.com", "Meta (Instagram / Facebook)"),
    ("twitter.com", "X (Twitter)"),
    ("x.com", "X (Twitter)"),
    ("twimg.com", "X (Twitter)"),
    ("t.co", "X (Twitter)"),
    ("snapchat", "Snapchat"),
    ("sc-cdn.net", "Snapchat"),
    ("discord", "Discord"),
    ("reddit", "Reddit"),
    ("redd.it", "Reddit"),
    ("linkedin", "LinkedIn"),
    ("pinterest", "Pinterest"),
    ("pinimg.com", "Pinterest"),
    ("threads.net", "Threads"),

    # Video & Music Streaming
    ("googlevideo.com", "YouTube"),
    ("youtubei.googleapis", "YouTube (Mobile App)"),
    ("youtube.com", "YouTube"),
    ("ytimg.com", "YouTube"),
    ("youtu.be", "YouTube"),
    ("ggpht.com", "YouTube"),
    ("spotify", "Spotify"),
    ("scdn.co", "Spotify"),
    ("netflix", "Netflix"),
    ("nflxvideo", "Netflix"),
    ("twitch.tv", "Twitch"),
    ("ttvnw.net", "Twitch"),
    ("soundcloud", "SoundCloud"),
    ("sndcdn.com", "SoundCloud"),

    # General Google / Apple / Microsoft
    ("www.google.", "Google Search"),
    ("google.com", "Google Search / Services"),
    ("icloud.com", "Apple iCloud"),
    ("apple.com", "Apple Services"),
    ("microsoft.com", "Microsoft Services"),
    ("live.com", "Microsoft / Outlook"),
]

# Background phone telemetry/push domains to ignore
IGNORE_DOMAINS = (
    "connectivitycheck.gstatic.com",
    "mtalk.google.com",
    "alt1-mtalk.google.com",
    "alt2-mtalk.google.com",
    "alt3-mtalk.google.com",
    "alt4-mtalk.google.com",
    "alt5-mtalk.google.com",
    "alt6-mtalk.google.com",
    "alt7-mtalk.google.com",
    "alt8-mtalk.google.com",
    "app-measurement.com",
    "crashlytics.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "firebaselogging",
    "play.fe.googleapis.com",
    "android.clients.google.com",
    "gstatic.com",
    "googleapis.com",
)

# Shared Caches & State
sni_cache = {}            # ip -> sni domain
first_seen_ip = {}        # ip -> timestamp when ss first saw it
ip_cache = {}             # ip -> fallback resolved name
recent_logs = {}          # service_name -> last printed timestamp
sni_active_boost = {}     # service_name -> expiry timestamp (keeps short HTTPS bursts active)
app_stats = {}            # service_name -> dict of usage metrics
timeline_logs = []        # chronological list of logged events
user_currently_connected = False
stop_requested = False

COOLDOWN = 8              # Seconds between duplicate live console prints
SNI_BOOST_SECONDS = 5.0   # Minimum active window credited when an SNI handshake occurs
state_lock = threading.Lock()

compiled_ranges = {
    app: [ipaddress.ip_network(cidr) for cidr in cidrs]
    for app, cidrs in APP_IP_RANGES.items()
}

def signal_handler(sig, frame):
    global stop_requested
    stop_requested = True

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def verify_user(username):
    try:
        return pwd.getpwnam(username).pw_uid
    except KeyError:
        print(f"[!] Error: User '{username}' does not exist on this server.")
        sys.exit(1)

def parse_duration(duration_str):
    """Parses formats like '24h0m', '2h30m', '24h', '45m' into total seconds."""
    s = duration_str.strip().lower()
    pattern = r"^(?:(\d+)\s*h)?\s*(?:(\d+)\s*m)?\s*(?:(\d+)\s*s)?$"
    match = re.match(pattern, s)
    if not match or not any(match.groups()):
        return None
    hours = int(match.group(1)) if match.group(1) else 0
    minutes = int(match.group(2)) if match.group(2) else 0
    seconds = int(match.group(3)) if match.group(3) else 0
    total = (hours * 3600) + (minutes * 60) + seconds
    return total if total > 0 else None

def format_seconds(sec):
    """Formats seconds into Xh Ym Zs."""
    sec = int(round(sec))
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    return f"{h:02d}h {m:02d}m {s:02d}s"

def get_server_local_ips_and_ports():
    local_ips = {"127.0.0.1", "::1", "0.0.0.0", "::"}
    listen_ports = {"22"}
    try:
        out = subprocess.check_output(["hostname", "-I"], stderr=subprocess.DEVNULL).decode("utf-8")
        for ip in out.split():
            local_ips.add(ip.strip())
    except Exception:
        pass

    try:
        out = subprocess.check_output(["ss", "-tlnH"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                port = parts[3].rsplit(":", 1)[-1]
                listen_ports.add(port)
    except Exception:
        pass

    return local_ips, listen_ports

def clean_ip(addr_str):
    if addr_str.startswith("["):
        ip_part = addr_str.split("]:")[0][1:]
    else:
        ip_part = addr_str.rsplit(":", 1)[0]
    if ip_part.startswith("::ffff:"):
        ip_part = ip_part.replace("::ffff:", "")
    return ip_part

def check_static_ranges(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for app, networks in compiled_ranges.items():
            for net in networks:
                if ip_obj in net:
                    return app
    except ValueError:
        pass
    return None

def classify_domain(domain):
    d = domain.lower().strip(".")
    if not d:
        return None
    for kw, app_name in KEYWORDS_MAP:
        if kw in d:
            return app_name
    for ign in IGNORE_DOMAINS:
        if ign in d:
            return "IGNORE"
    clean_d = re.sub(r"^www\.", "", d)
    return f"Web / App ({clean_d})"

def record_app_event(service_name, ip_str, domain_str=None, boost_activity=False):
    if not service_name or service_name == "IGNORE":
        return
    now = time.time()
    now_dt_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    time_only_str = datetime.now().strftime("%H:%M:%S")

    with state_lock:
        if service_name not in app_stats:
            app_stats[service_name] = {
                "usage_seconds": 0.0,
                "event_count": 0,
                "first_seen": now_dt_str,
                "last_seen": now_dt_str,
                "domains": set(),
                "ips": set()
            }
        st = app_stats[service_name]
        st["last_seen"] = now_dt_str
        if ip_str:
            st["ips"].add(ip_str)
        if domain_str:
            st["domains"].add(domain_str.lower())

        if boost_activity:
            sni_active_boost[service_name] = now + SNI_BOOST_SECONDS

        last_seen = recent_logs.get(service_name, 0)
        if now - last_seen > COOLDOWN:
            st["event_count"] += 1
            recent_logs[service_name] = now
            timeline_logs.append({
                "timestamp": now_dt_str,
                "application": service_name,
                "destination_ip": ip_str,
                "domain": domain_str or sni_cache.get(ip_str, "")
            })
            print(f"{time_only_str:<10} | {service_name:<42} | {ip_str}", flush=True)

def sni_and_dns_sniffer():
    """Captures live TLS SNI and DNS responses to map IPs to exact app names immediately."""
    cmd = [
        "tshark", "-l", "-n", "-i", "any",
        "-Y", "tls.handshake.type == 1 or (dns.flags.response == 1 and dns.a)",
        "-T", "fields",
        "-e", "ip.dst",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "dns.qry.name",
        "-e", "dns.a"
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            if stop_requested:
                proc.terminate()
                break
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            dst_ip = parts[0].split(",")[0].strip()
            sni_name = parts[1].split(",")[0].strip() if len(parts) > 1 else ""
            dns_qry = parts[2].split(",")[0].strip() if len(parts) > 2 else ""
            dns_a = parts[3].split(",") if len(parts) > 3 else []

            if sni_name and dst_ip:
                sni_cache[dst_ip] = sni_name
                if user_currently_connected:
                    app_label = classify_domain(sni_name)
                    if app_label and app_label != "IGNORE":
                        record_app_event(app_label, dst_ip, domain_str=sni_name, boost_activity=True)

            if dns_qry and dns_a:
                for resolved_ip in dns_a:
                    resolved_ip = resolved_ip.strip()
                    if resolved_ip and resolved_ip not in sni_cache:
                        sni_cache[resolved_ip] = dns_qry
    except Exception:
        pass

def get_user_sshd_pids(username):
    pids = set()
    try:
        out = subprocess.check_output(["ps", "-eo", "pid,comm,args"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in out.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) < 3:
                continue
            pid_str, comm, args = parts
            if "sshd" not in comm:
                continue
            if re.search(rf"sshd:\s+{re.escape(username)}(\s|@|\[|$)", args):
                pids.add(pid_str)
    except Exception:
        pass
    return pids

def get_active_connections(pids, local_ips, listen_ports):
    destinations = set()
    if not pids:
        return destinations
    try:
        out = subprocess.check_output(["ss", "-tupn"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in out.splitlines():
            if "ESTAB" not in line and "SYN-SENT" not in line:
                continue
            if not any(f"pid={pid}," in line for pid in pids):
                continue

            parts = line.split()
            try:
                state_idx = parts.index("ESTAB") if "ESTAB" in parts else parts.index("SYN-SENT")
            except ValueError:
                continue

            if len(parts) <= state_idx + 4:
                continue

            local_addr = parts[state_idx + 3]
            peer_addr = parts[state_idx + 4]

            local_port = local_addr.rsplit(":", 1)[-1]
            peer_port = peer_addr.rsplit(":", 1)[-1]

            if local_port in listen_ports:
                continue
            if peer_port in ("5228", "5229", "5230"):
                continue

            peer_ip = clean_ip(peer_addr)
            if peer_ip in local_ips or peer_ip.startswith(("127.", "10.", "192.168.", "172.16.")):
                continue

            destinations.add(peer_ip)
    except Exception:
        pass
    return destinations

def identify_by_ip_fallback(ip_str):
    if ip_str in ip_cache:
        return ip_cache[ip_str]
    try:
        rdns = socket.gethostbyaddr(ip_str)[0].lower()
        for kw, app_name in KEYWORDS_MAP:
            if kw in rdns:
                ip_cache[ip_str] = app_name
                return app_name
        for ign in IGNORE_DOMAINS:
            if ign in rdns:
                ip_cache[ip_str] = "IGNORE"
                return "IGNORE"
    except Exception:
        pass
    ip_cache[ip_str] = None
    return None

def build_report_dict(username, uid, duration_input, target_seconds, start_dt, elapsed_total, ssh_connected_sec, active_usage_sec):
    now_dt = datetime.now()
    idle_connected_sec = max(0.0, ssh_connected_sec - active_usage_sec)

    # Calculate averages
    monitored_hours = max(elapsed_total / 3600.0, 0.0001)
    connected_hours = ssh_connected_sec / 3600.0
    active_hours = active_usage_sec / 3600.0

    # Projected daily average (how many hours per 24h the user is actively using apps)
    daily_avg_active_hours = (active_usage_sec / elapsed_total) * 24.0 if elapsed_total > 0 else 0.0
    daily_avg_connected_hours = (ssh_connected_sec / elapsed_total) * 24.0 if elapsed_total > 0 else 0.0
    avg_active_mins_per_hour = (active_usage_sec / 60.0) / monitored_hours if elapsed_total > 0 else 0.0
    active_ratio_of_connected = (active_usage_sec / ssh_connected_sec * 100.0) if ssh_connected_sec > 0 else 0.0
    active_ratio_of_monitored = (active_usage_sec / elapsed_total * 100.0) if elapsed_total > 0 else 0.0

    with state_lock:
        sorted_apps = sorted(
            app_stats.items(),
            key=lambda x: x[1]["usage_seconds"],
            reverse=True
        )
        apps_report = {}
        for app_name, st in sorted_apps:
            u_sec = round(st["usage_seconds"], 2)
            pct = round((u_sec / active_usage_sec * 100.0), 2) if active_usage_sec > 0 else 0.0
            apps_report[app_name] = {
                "usage_seconds": u_sec,
                "usage_formatted": format_seconds(u_sec),
                "usage_hours": round(u_sec / 3600.0, 3),
                "percentage_of_active_traffic": pct,
                "session_triggers": st["event_count"],
                "first_seen": st["first_seen"],
                "last_seen": st["last_seen"],
                "domains_seen": sorted(list(st["domains"]))[:25],
                "destination_ips": sorted(list(st["ips"]))[:25]
            }

        logs_copy = list(timeline_logs)

    return {
        "metadata": {
            "username": username,
            "uid": uid,
            "start_time": start_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "last_updated_or_end_time": now_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "requested_duration_input": duration_input,
            "requested_duration_seconds": target_seconds,
            "actual_monitored_seconds": round(elapsed_total, 2),
            "actual_monitored_formatted": format_seconds(elapsed_total)
        },
        "connection_summary": {
            "total_ssh_connected_seconds": round(ssh_connected_sec, 2),
            "total_ssh_connected_formatted": format_seconds(ssh_connected_sec),
            "total_ssh_connected_hours": round(connected_hours, 2),
            "active_traffic_usage_seconds": round(active_usage_sec, 2),
            "active_traffic_usage_formatted": format_seconds(active_usage_sec),
            "active_traffic_usage_hours": round(active_hours, 2),
            "idle_connected_seconds": round(idle_connected_sec, 2),
            "idle_connected_formatted": format_seconds(idle_connected_sec)
        },
        "averages_and_analytics": {
            "average_active_minutes_per_monitored_hour": round(avg_active_mins_per_hour, 2),
            "projected_daily_active_usage_hours_per_24h": round(daily_avg_active_hours, 2),
            "projected_daily_Active_usage_formatted": format_seconds(daily_avg_active_hours * 3600),
            "projected_daily_connected_hours_per_24h": round(daily_avg_connected_hours, 2),
            "active_usage_percentage_while_connected": round(active_ratio_of_connected, 2),
            "active_usage_percentage_of_total_window": round(active_ratio_of_monitored, 2),
            "total_unique_services_used": len(apps_report),
            "total_logged_events": len(logs_copy)
        },
        "applications_breakdown": apps_report,
        "timeline_events": logs_copy
    }

def save_json_report(filepath, report_data):
    temp_path = filepath + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)
    subprocess.run(["mv", "-f", temp_path, filepath], stderr=subprocess.DEVNULL)

def print_final_report(report_data, filepath):
    meta = report_data["metadata"]
    conn = report_data["connection_summary"]
    avg = report_data["averages_and_analytics"]
    apps = report_data["applications_breakdown"]

    print("\n" + "=" * 78)
    print("                      FINAL USER TRAFFIC & USAGE REPORT                      ")
    print("=" * 78)
    print(f" User Monitored            : {meta['username']} (UID: {meta['uid']})")
    print(f" Monitoring Period         : {meta['start_time']}  -->  {meta['last_updated_or_end_time']}")
    print(f" Total Monitored Duration  : {meta['actual_monitored_formatted']} (Target: {meta['requested_duration_input']})")
    print("-" * 78)
    print(" [CONNECTION & ACTIVITY METRICS]")
    print(f"  * Total SSH Connected Time : {conn['total_ssh_connected_formatted']} ({conn['total_ssh_connected_hours']} hrs)")
    print(f"  * Active App Usage Time    : {conn['active_traffic_usage_formatted']} ({conn['active_traffic_usage_hours']} hrs)")
    print(f"  * Idle Connected Time      : {conn['idle_connected_formatted']}")
    print("-" * 78)
    print(" [AVERAGES & ANALYTICS]")
    print(f"  * Avg Active Usage / Hour  : {avg['average_active_minutes_per_monitored_hour']} mins per hour")
    print(f"  * Daily Avg Active Usage   : {avg['projected_daily_active_usage_hours_per_24h']} hrs / 24h ({avg['projected_daily_Active_usage_formatted']})")
    print(f"  * Daily Avg SSH Connected  : {avg['projected_daily_connected_hours_per_24h']} hrs / 24h")
    print(f"  * Activity Efficiency      : {avg['active_usage_percentage_while_connected']}% of connected time was active")
    print("-" * 78)
    print(" [APPLICATION USAGE BREAKDOWN]")
    if not apps:
        print("  No application traffic was recorded during this session.")
    else:
        print(f"  {'APPLICATION / SERVICE':<36} | {'DURATION':<12} | {'HOURS':<7} | {'SHARE':<7} | {'EVENTS'}")
        print("  " + "-" * 74)
        for app_name, info in apps.items():
            print(
                f"  {app_name:<36} | {info['usage_formatted']:<12} | "
                f"{info['usage_hours']:<7.2f} | {info['percentage_of_active_traffic']:>5.1f}%  | {info['session_triggers']}"
            )
    print("=" * 78)
    print(f"[+] Complete JSON report saved to: {filepath}\n")

def main():
    global user_currently_connected

    print("=" * 78)
    print("          SSH TUNNEL TIMED USER MONITOR & JSON ANALYTICS GENERATOR          ")
    print("=" * 78)

    if len(sys.argv) >= 3:
        username = sys.argv[1].strip()
        duration_input = sys.argv[2].strip()
    else:
        username = input("1. Enter Linux Username to monitor : ").strip()
        duration_input = input("2. Enter Duration (e.g. 24h0m, 2h30m, 45m) : ").strip()

    uid = verify_user(username)
    target_seconds = parse_duration(duration_input)
    while not target_seconds:
        print("[!] Invalid format. Use XhYm format like '24h0m', '1h30m', '12h', or '30m'.")
        duration_input = input("2. Enter Duration (e.g. 24h0m, 2h30m, 45m) : ").strip()
        target_seconds = parse_duration(duration_input)

    local_ips, listen_ports = get_server_local_ips_and_ports()

    start_dt = datetime.now()
    end_dt = start_dt + timedelta(seconds=target_seconds)
    json_filename = f"{username}_{start_dt.strftime('%Y-%m-%d_%H-%M-%S')}.json"

    # Start live SNI + DNS sniffer thread
    t = threading.Thread(target=sni_and_dns_sniffer, daemon=True)
    t.start()

    print(f"\n[+] Monitoring User      : '{username}' (UID: {uid})")
    print(f"[+] Target Duration      : {duration_input} ({format_seconds(target_seconds)})")
    print(f"[+] Scheduled End Time   : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[+] JSON Output File     : {json_filename} (Auto-saves every 30s)")
    print("[+] Press Ctrl+C at any time to stop early and generate the report.\n")
    print(f"{'TIME':<10} | {'APPLICATION / SERVICE':<42} | {'DESTINATION IP'}")
    print("-" * 78)

    start_ts = time.time()
    last_tick = start_ts
    last_autosave = start_ts

    ssh_connected_seconds = 0.0
    active_usage_seconds = 0.0

    while not stop_requested:
        now = time.time()
        dt = now - last_tick
        last_tick = now
        elapsed_total = now - start_ts

        if elapsed_total >= target_seconds:
            break

        pids = get_user_sshd_pids(username)
        is_connected = len(pids) > 0
        user_currently_connected = is_connected

        if is_connected:
            ssh_connected_seconds += dt

            active_ips = get_active_connections(pids, local_ips, listen_ports)
            active_apps_this_tick = set()

            for ip in active_ips:
                # 1. Check static IP ranges (Telegram, WhatsApp, TikTok)
                static_app = check_static_ranges(ip)
                if static_app:
                    record_app_event(static_app, ip)
                    active_apps_this_tick.add(static_app)
                    continue

                # 2. Check SNI/DNS cache
                if ip in sni_cache:
                    domain = sni_cache[ip]
                    app_label = classify_domain(domain)
                    if app_label and app_label != "IGNORE":
                        record_app_event(app_label, ip, domain_str=domain)
                        active_apps_this_tick.add(app_label)
                    continue

                # 3. Wait 1.2s for tshark SNI before trying rDNS fallback
                if ip not in first_seen_ip:
                    first_seen_ip[ip] = now
                    continue
                if now - first_seen_ip[ip] >= 1.2:
                    fallback_app = identify_by_ip_fallback(ip)
                    if fallback_app and fallback_app != "IGNORE":
                        record_app_event(fallback_app, ip)
                        active_apps_this_tick.add(fallback_app)

            # Include recently boosted SNI apps (for short HTTPS bursts)
            with state_lock:
                for boosted_app, exp_ts in list(sni_active_boost.items()):
                    if now < exp_ts:
                        active_apps_this_tick.add(boosted_app)
                    else:
                        del sni_active_boost[boosted_app]

                if active_apps_this_tick:
                    active_usage_seconds += dt
                    for app_name in active_apps_this_tick:
                        if app_name in app_stats:
                            app_stats[app_name]["usage_seconds"] += dt

        # Periodic Auto-Save every 30 seconds
        if now - last_autosave >= 30.0:
            report_data = build_report_dict(
                username, uid, duration_input, target_seconds,
                start_dt, elapsed_total, ssh_connected_seconds, active_usage_seconds
            )
            save_json_report(json_filename, report_data)
            last_autosave = now

        time.sleep(0.5)

    # Final Save and Report Generation
    elapsed_total = min(time.time() - start_ts, float(target_seconds)) if not stop_requested else (time.time() - start_ts)
    final_report = build_report_dict(
        username, uid, duration_input, target_seconds,
        start_dt, elapsed_total, ssh_connected_seconds, active_usage_seconds
    )
    save_json_report(json_filename, final_report)
    print_final_report(final_report, json_filename)

if __name__ == "__main__":
    main()
