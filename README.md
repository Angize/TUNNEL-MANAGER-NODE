# TUNNEL-MANAGER-NODE

ایجنتِ خودکفای نود: از پنل config می‌گیرد، تونل و پورت‌فوروارد می‌سازد، بعد از ریبوت
بازمی‌سازد و تغییرِ آی‌پی را به پنل خبر می‌دهد. تونل‌ها مستقیم بینِ نودها جریان دارند؛
پنل فقط فرمان می‌دهد.

> ساده‌ترین راه اصلاً دستی نیست: در پنل **«افزودنِ نود → خودکار»** فقط SSHِ سرور را بده؛
> پنل خودش وارد می‌شود، ایجنت را نصب می‌کند و نود را وصل می‌کند. مراحلِ زیر نصبِ دستی است.

## پیش‌نیاز

| ابزار | برای چه |
|---|---|
| `python3` | اجرای ایجنت |
| `iproute2` (`ip`) | ساختِ تونل‌های کرنلی |
| `iptables` | پورت‌فوروارد + شمارشِ ترافیک |
| Linux + systemd | سرویسِ ماندگار |

بدونِ OpenvSwitch — همهٔ تونل‌ها netdevِ نیتیوِ کرنل‌اند. هستهٔ رمزنگاری‌شده را پنل
push می‌کند (روی نود ساخته نمی‌شود).

## راه‌اندازی از صفر

```bash
# ۱) پیش‌نیازها (Debian/Ubuntu)
sudo apt update && sudo apt install -y python3 iproute2 iptables git

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
| `--auto-install <port>` | نصبِ غیرتعاملی (همان چیزی که پنل اجرا می‌کند؛ پیش‌فرض `8099`) |
| `--show` | نمایشِ `host / port / token` برای ثبت در پنل |

**بروزرسانی:** از پنل، تبِ **تنظیمات → بروزرسانیِ ایجنت** (آپلود و push، بدونِ SSH).

## چه می‌سازد

| نوع | جزئیات |
|---|---|
| `core` | تونلِ رمزنگاری‌شدهٔ هسته (udp/tcp/raw/flux/ws) |
| kernel | VXLAN · GRE · SIT · IPIP · L2TPv3 · FOU · IPsec |
| forward | پورت‌فورواردِ TCP+UDP با چرخشِ چند مقصد |

---

کنترل‌پنل 👉 [tnl-central](https://github.com/Angize/TUNNEL-MANAGER) • مجوز 👉 [LICENSE](./LICENSE)
