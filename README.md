# TUNNEL-MANAGER-NODE

## نصب

روی سرورِ نود — Debian/Ubuntu با systemd، به‌عنوان root:

```bash
curl -fsSL https://raw.githubusercontent.com/Angize/TUNNEL-MANAGER-NODE/main/tnl-node.py -o /tmp/tnl-node.py && sudo python3 /tmp/tnl-node.py --install
```

نصب‌کننده خودش پیش‌نیازها را می‌گیرد (`iproute2`, `iptables`, `openssl`, `procps`, `kmod`,
`ca-certificates`)، پورت می‌پرسد (پیش‌فرض `8099`)، توکن می‌سازد، سرویسِ systemd را بالا
می‌آورد، و در پایان `host / port / token` را چاپ می‌کند — همان‌ها را در تبِ «نودها»ی پنل ثبت کن.

پورت را می‌شود بدونِ سؤال هم داد: `--install 9099`.

**راهِ کوتاه‌تر:** در پنل **«افزودنِ نود → خودکار»** فقط SSHِ سرور را بده؛ پنل خودش وارد
می‌شود، همین ایجنت را نصب می‌کند و نود را ثبت می‌کند. آن‌وقت هیچ‌کدام از مراحلِ بالا لازم نیست.

## بروزرسانی

از پنل: **تنظیمات → بروزرسانیِ ایجنت** (بدونِ SSH، با امضای RSA).

## دستورها

| دستور | کار |
|---|---|
| `sudo python3 tnl-node.py --install [port]` | نصب |
| `sudo python3 tnl-node.py --auto-install [port]` | نصبِ غیرتعاملی (همان که پنل اجرا می‌کند) |
| `sudo python3 tnl-node.py --show` | چاپِ `host / port / token` |
| `sudo python3 tnl-node.py` | منویِ root: نصب / نمایش / ری‌استارت / تغییرِ پورت / بازتولیدِ توکن / وضعیت / حذف |

## حذف

```bash
sudo python3 /opt/tunnel/tnl-node.py    # گزینهٔ ۷) Uninstall
```

---

کنترل‌پنل 👉 [tnl-central](https://github.com/Angize/TUNNEL-MANAGER) • هسته 👉 [tnl-core](https://github.com/Angize/TUNNEL-MANAGER-CORE) • مجوز 👉 [LICENSE](./LICENSE)
