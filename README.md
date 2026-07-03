<div align="center">

# 🛰️ tnl-node

**ایجنتِ خودکفای نود** برای [tnl-central](https://github.com/Angize/TUNNEL-MANAGER)
خودش تونل و پورت‌فوروارد می‌سازد و بعد از ریبوت بازمی‌سازد.

![Python](https://img.shields.io/badge/Python-3.7%2B-3776AB?logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-systemd-333?logo=linux&logoColor=white)
![auth](https://img.shields.io/badge/auth-token-e67e22)

</div>

---

## ⚡ نصب

روی هر سرورِ **نود** — تک‌خطی (با توکنِ دسترسی، چون ریپو private است):

```bash
curl -fsSL -H "Authorization: token <TOKEN>" https://raw.githubusercontent.com/Angize/TUNNEL-MANAGER-NODE/main/tnl-node.py -o tnl-node.py && sudo python3 tnl-node.py --install
```

> `<TOKEN>` = یک GitHub PAT با دسترسیِ **Contents: Read**.
> جایگزینِ git: `git clone https://github.com/Angize/TUNNEL-MANAGER-NODE.git && cd TUNNEL-MANAGER-NODE && sudo python3 tnl-node.py --install`

**بروزرسانی:** از پنل، تبِ **«بروزرسانیِ ایجنت»** → آپلود و push (بدونِ SSH).

---

## 🔗 ثبت در پنل

```bash
sudo python3 tnl-node.py --show
```

`host / port / token` را در تبِ **«نودها»**ی پنل وارد کن. تمام.

---

## ✨ قابلیت‌ها

- 🧩 VXLAN / GRE / SIT
- 🔀 پورت‌فورواردِ TCP+UDP با چرخش
- ♻️ بازسازیِ خودکار بعد از بوت
- 📞 خبردادن به پنل هنگام تغییرِ آی‌پی
- 🔐 APIِ توکن‌دار

**پیش‌نیاز:** Python 3 · iproute2 · iptables · openvswitch (برای VXLAN/GRE)

---

<div align="center">

کنترل‌پنل 👉 [**tnl-central**](https://github.com/Angize/TUNNEL-MANAGER) • مجوز 👉 [LICENSE](./LICENSE)

</div>
