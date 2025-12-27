
import os
import sys
import time
import atexit
import sqlite3
import requests
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from win10toast import ToastNotifier

# --- الإعدادات الاحترافية ---
THRESHOLD = 40  # عدد الحزم في الثانية المسموح بها
DISCORD_WEBHOOK_URL = "" # استبدل هذا بالرابط الخاص بك

blocked_ips = set()
packet_count = defaultdict(int)
start_time = [time.time()]
toaster = ToastNotifier()

# --- إعداد قاعدة البيانات ---
def setup_database():
    conn = sqlite3.connect("sentinel_x_global.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS security_logs 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       timestamp TEXT, 
                       ip TEXT, 
                       reason TEXT, 
                       country TEXT, 
                       city TEXT, 
                       isp TEXT)''')
    conn.commit()
    conn.close()

def log_to_db(ip, reason, geo):
    conn = sqlite3.connect("sentinel_x_global.db")
    cursor = conn.cursor()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    country = geo['country'] if geo else "Internal"
    city = geo['city'] if geo else "Internal"
    isp = geo['isp'] if geo else "N/A"
    cursor.execute("INSERT INTO security_logs (timestamp, ip, reason, country, city, isp) VALUES (?, ?, ?, ?, ?, ?)",
                   (timestamp, ip, reason, country, city, isp))
    conn.commit()
    conn.close()

# --- نظام الاستخبارات الجغرافية (GeoIP) ---
def get_ip_info(ip):
    if ip in ["127.0.0.1", "localhost"] or ip.startswith("192.168."):
        return None
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if response.get('status') == 'success':
            return {
                "country": response.get("country", "Unknown"),
                "countryCode": response.get("countryCode", "UN"),
                "city": response.get("city", "Unknown"),
                "isp": response.get("isp", "Unknown"),
                "lat": response.get("lat", 0),
                "lon": response.get("lon", 0)
            }
    except:
        pass
    return None

# --- نظام تنبيهات فريق Sentinel X ---
def send_global_alert(ip, reason, rate):
    if "YOUR_WEBHOOK" in DISCORD_WEBHOOK_URL: return
    
    geo = get_ip_info(ip)
    flag = f":flag_{geo['countryCode'].lower()}:" if geo else "🛡️"
    location = f"{geo['city']}, {geo['country']}" if geo else "Internal Network"
    map_url = f"https://www.google.com/maps?q={geo['lat']},{geo['lon']}" if geo else ""

    data = {
        "username": "Sentinel X Intelligence",
        "avatar_url": "https://i.imgur.com/8n9X79X.png",
        "embeds": [{
            "title": f"{flag} Threat Blocked & Neutralized",
            "color": 15158332, # Red Color
            "fields": [
                {"name": "👤 Attacker IP", "value": f"`{ip}`", "inline": True},
                {"name": "🔍 Reason", "value": reason, "inline": True},
                {"name": "📊 Rate", "value": f"{rate} pkt/s", "inline": True},
                {"name": "📍 Location", "value": location, "inline": False},
                {"name": "🏢 ISP", "value": geo['isp'] if geo else "N/A", "inline": True},
            ],
            "footer": {"text": f"Sentinel X Global Protection System • {time.strftime('%H:%M:%S')}"}
        }]
    }
    
    if map_url:
        data["embeds"][0]["fields"].append({"name": "🗺️ Google Maps", "value": f"[View Location]({map_url})", "inline": True})

    try:
        requests.post(DISCORD_WEBHOOK_URL, json=data)
    except:
        print("Failed to send Discord alert.")

# --- وظائف الحماية الأساسية ---
def block_ip(ip, reason, rate=0):
    if ip not in blocked_ips:
        # تنفيذ الحظر في جدار حماية ويندوز
        os.system(f'netsh advfirewall firewall add rule name="SentinelX_Block_{ip}" dir=in action=block remoteip={ip}')
        blocked_ips.add(ip)
        
        # جلب معلومات الموقع الجغرافي
        geo = get_ip_info(ip)
        
        # تنفيذ الإجراءات الاحترافية
        log_to_db(ip, reason, geo)
        send_global_alert(ip, reason, rate)
        toaster.show_toast("Sentinel X Alert", f"Blocked: {ip}\nReason: {reason}", duration=5)
        
        print(f"\n[{time.strftime('%H:%M:%S')}] 🔥 ALERT: {reason} from {ip}")
        if geo: print(f"    Location: {geo['city']}, {geo['country']} | ISP: {geo['isp']}")

def cleanup():
    """تنظيف القواعد عند الخروج من البرنامج"""
    print("\n[!] Shutting down Sentinel X... Clearing Firewall rules...")
    for ip in list(blocked_ips):
        os.system(f'netsh advfirewall firewall delete rule name="SentinelX_Block_{ip}"')
    print("[+] System Secured & Cleaned.")

atexit.register(cleanup)

def packet_callback(packet):
    if IP not in packet: return
    src_ip = packet[IP].src

    # 1. فحص تواقيع الفيروسات (Deep Packet Inspection)
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = bytes(packet[TCP].payload)
        if b"GET /scripts/root.exe" in payload:
            block_ip(src_ip, "Nimda Worm Signature")
            return

    # 2. مراقبة السلوك وحجم البيانات (Behavioral Analysis)
    packet_count[src_ip] += 1
    current_time = time.time()
    if current_time - start_time[0] >= 1:
        for ip, count in list(packet_count.items()):
            if count > THRESHOLD:
                block_ip(ip, "Flood Attack (DoS)", count)
        packet_count.clear()
        start_time[0] = current_time

# --- نقطة انطلاق البرنامج ---
if __name__ == "__main__":
    setup_database()
    print("""
    ==================================================
       🛡️  SENTINEL X - GLOBAL INTELLIGENCE EDITION
    ==================================================
    [*] Monitoring Network Traffic...
    [*] Database: sentinel_x_global.db (Active)
    [*] Discord Alerts: Active
    [!] Press Ctrl+C to stop.
    """)
    
    try:
        # بدء مراقبة الشبكة (Store=0 لضمان عدم استهلاك الذاكرة)
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:

        sys.exit(0)
