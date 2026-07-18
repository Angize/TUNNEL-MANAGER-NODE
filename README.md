# TUNNEL-MANAGER-NODE

ایجنتِ خودکفای نود: یک فایلِ Pythonِ تک‌فایلِ root که از پنل فرمان می‌گیرد، تونل و
پورت‌فوروارد می‌سازد، هستهٔ رمزنگاری‌شده را زیرِ systemd اجرا و نگه‌بانی می‌کند، بعد از
ریبوت همه را بازمی‌سازد و تغییرِ آی‌پی را به پنل خبر می‌دهد. تونل‌ها مستقیم بینِ نودها
جریان دارند؛ پنل فقط فرمان می‌دهد. فقط `python3` + `iproute2` + `iptables` + `openssl`
(بدونِ وابستگیِ خارجی، فقط stdlib).

> ساده‌ترین راه اصلاً دستی نیست: در پنل **«افزودنِ نود → خودکار»** فقط SSHِ سرور را بده؛
> پنل خودش وارد می‌شود، ایجنت را نصب می‌کند و نود را وصل می‌کند. مراحلِ زیر نصبِ دستی است.

## پیش‌نیاز

| ابزار | برای چه |
|---|---|
| `python3` | اجرای ایجنت (stdlib، بدونِ وابستگیِ خارجی) |
| `iproute2` (`ip`) | ساختِ تونل‌های کرنلی |
| `iptables` | پورت‌فوروارد + شمارشِ ترافیک |
| `openssl` | راستی‌آزماییِ امضای بروزرسانی |
| Linux + systemd | سرویسِ ماندگار |

بدونِ OpenvSwitch — همهٔ تونل‌های کرنلی netdevِ نیتیوِ کرنل‌اند. هستهٔ رمزنگاری‌شده را
پنل push می‌کند (روی نود ساخته نمی‌شود).

## راه‌اندازی از صفر

```bash
# ۱) پیش‌نیازها (Debian/Ubuntu)
sudo apt update && sudo apt install -y python3 iproute2 iptables openssl git

# ۲) دریافتِ کد
git clone https://github.com/Angize/TUNNEL-MANAGER-NODE.git
cd TUNNEL-MANAGER-NODE
# یا تک‌فایل بدونِ git:
# curl -fsSL https://raw.githubusercontent.com/Angize/TUNNEL-MANAGER-NODE/main/tnl-node.py -o tnl-node.py

# ۳) نصب (سرویسِ systemd + توکن می‌سازد)
sudo python3 tnl-node.py --install

# ۴) نمایشِ مشخصات و ثبت در پنل
sudo python3 tnl-node.py --show      # host / port / token → در تبِ «نودها»ی پنل
```

## دستورها

| دستور | کار |
|---|---|
| `--install` | نصبِ تعاملیِ سرویسِ systemd + ساختِ توکن |
| `--auto-install [port]` | نصبِ غیرتعاملی (همان چیزی که پنل اجرا می‌کند؛ پیش‌فرض `8099`) |
| `--show` | نمایشِ `host / port / token` برای ثبت در پنل |
| `--serve` | اجرای سرورِ API (سرویسِ systemd همین را صدا می‌زند) |
| بدونِ آرگومان | منویِ تعاملیِ root (نصب/نمایش/ری‌استارت/تغییرِ پورت/بازتولیدِ توکن/وضعیت/حذف) |

**بروزرسانی:** از پنل، تبِ **تنظیمات → بروزرسانیِ ایجنت** (آپلود و push، بدونِ SSH). هر
بروزرسانیِ کد **با امضای RSA** توسطِ پنل تأیید می‌شود؛ توکنِ لو‌رفتهٔ نود به‌تنهایی
نمی‌تواند کدِ مخرب push کند.

## چه می‌سازد

| نوع | جزئیات |
|---|---|
| `core` | تونلِ رمزنگاری‌شدهٔ هسته (`udp`/`tcp`/`raw`/`flux`/`ws`/`dns`) — با پنل کانفیگ می‌شود، هسته را زیرِ یونیتِ transientِ systemd اجرا می‌کند |
| kernel | VXLAN · GRE · SIT · IPIP · L2TPv3 · FOU · IPsec (ESPِ کلیدِ ثابت، بدونِ IKE) |
| forward | پورت‌فورواردِ TCP+UDP با چرخشِ چند مقصد + شمارشِ ماندگارِ ترافیک |

## API (که پنل صدا می‌زند)

سرورِ HTTPِ ساده روی `0.0.0.0:<port>` (پیش‌فرض `8099`) با احرازِ هدرِ **`X-Node-Token`**
(مقایسهٔ زمان‌ثابت). عملیاتِ فقط‌خواندنی (`ping`, `list`, `check`, `portcheck`,
`spoof-probe`, `edge-status`, `peer-status`) با GET؛ بقیه POST و زیرِ قفل. عملیاتِ
`update` و `core-install` علاوه بر توکن به **امضای RSA** هم نیاز دارند.

ارتباط با هسته از راهِ فایل‌های sidecar در کنارِ `core-<name>.json` است (status / peerpool /
srcpool که هسته می‌نویسد و ایجنت می‌خواند؛ و `.cmd`/`.echcmd` که ایجنت برای pin/چرخش/ECH
می‌نویسد)؛ «probe now» با `SIGHUP` به یونیتِ هسته می‌رود.

> ⚠️ API روی HTTPِ ساده است و فقط با توکن محافظت می‌شود — پورتِ ایجنت را **فقط به
> سرورِ مرکزی** باز کن (فایروال/شبکهٔ مطمئن). با هر تغییرِ IP، نود خودش پنل را از راهِ
> `/api/checkin` (توکن‌دار، با پینِ TOFUِ IPِ مرکزی) خبر می‌کند.

---

کنترل‌پنل 👉 [tnl-central](https://github.com/Angize/TUNNEL-MANAGER) • هسته 👉 [tnl-core](https://github.com/Angize/TUNNEL-MANAGER-CORE) • مجوز 👉 [LICENSE](./LICENSE)
