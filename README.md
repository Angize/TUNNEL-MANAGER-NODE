# TUNNEL-MANAGER-NODE

## نصب

روی سرورِ نود — Debian/Ubuntu با systemd، به‌عنوان root:

دستورِ نصب را از پنل بردار: **«افزودنِ نود → دستی»** همین دستور را با پورت و کلیدِ امضای همان
پنل نشان می‌دهد:

```bash
curl -fsSL https://github.com/Angize/TUNNEL-MANAGER-NODE/releases/latest/download/tnl-node.py -o /tmp/tnl-node.py
sudo python3 /tmp/tnl-node.py --install 8099 <panel-key>
```

نصب‌کننده خودش پیش‌نیازها را می‌گیرد (`iproute2`, `iptables`, `openssl`, `procps`, `kmod`,
`ca-certificates`)، کلیدِ امضای پنل را نگه می‌دارد، توکن می‌سازد، سرویسِ systemd را بالا
می‌آورد، و در پایان `host / port / token` را چاپ می‌کند — همان‌ها را در همان پنجرهٔ «دستی» وارد کن.

`--install` بدونِ کلید در ترمینال کلید را می‌پرسد. نودی که بدونِ کلید نصب شود (Enter در جوابِ همین سؤال،
یا نصبِ غیرتعاملی بدونِ کلید) آپدیتِ ایجنت و هسته را نمی‌پذیرد تا وقتی که با دستورِ پنل دوباره نصب شود؛
ایجنت کلید را از راهِ شبکه قبول نمی‌کند.

**راهِ کوتاه‌تر:** در پنل **«افزودنِ نود → خودکار»** فقط SSHِ سرور را بده؛ پنل خودش وارد
می‌شود، همین ایجنت را نصب می‌کند و نود را ثبت می‌کند. آن‌وقت هیچ‌کدام از مراحلِ بالا لازم نیست.

## ارتباط با پنل

پنل با ایجنت فقط روی TLS حرف می‌زند. ایجنت در اولین اجرا یک گواهیِ خودساختهٔ ده‌ساله در
`/opt/tunnel/tls.pem` می‌سازد و پنل اثرانگشتش را از جوابِ امضاشدهٔ خودِ ایجنت یاد می‌گیرد؛ نه گواهی
لازم است بخری، نه چیزی در پنل وارد کنی. برای عوض کردنِ گواهی همان فایل را پاک کن و
`systemctl restart tnl-node` بزن.

## بروزرسانی

از پنل: **تنظیمات → بروزرسانیِ ایجنت** (بدونِ SSH، با امضای RSA).

## دستورها

| دستور | کار |
|---|---|
| `sudo python3 tnl-node.py --install [port] [panel-key]` | نصب |
| `sudo python3 tnl-node.py --auto-install [port] [panel-key]` | نصبِ غیرتعاملی (همان که پنل با SSH اجرا می‌کند) |
| `sudo python3 tnl-node.py --show` | چاپِ `host / port / token` |
| `sudo python3 tnl-node.py` | منویِ root: نصب / نمایش / ری‌استارت / تغییرِ پورت / بازتولیدِ توکن / وضعیت / حذف |

## حذف

```bash
sudo python3 /opt/tunnel/tnl-node.py    # گزینهٔ ۷) Uninstall
```

---

کنترل‌پنل 👉 [tnl-central](https://github.com/Angize/TUNNEL-MANAGER) • هسته 👉 [tnl-core](https://github.com/Angize/TUNNEL-MANAGER-CORE) • مجوز 👉 [LICENSE](./LICENSE)
