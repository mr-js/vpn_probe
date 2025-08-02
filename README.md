# vpn_probe
Probe all your vpn-configs in one click [multithreaded]

![vpn_probe](/images/vpn_probe.png)

## Features

Support ready configs for Nekoray (V2Ray):

✅ vmess
✅ vless
✅ trojan
✅ trojan
✅ ss

Lightweight, multithreaded and full native cross platform console app! Only one decorative dependency: console progress bar [requirements.txt](/requirements.txt)


## Usage

1. Run [app.py](/app.py) and select folder with configs for probe (measure latency), for example:

```
# test.txt:
vmess://eyJ .. Q==
vless://e7c .. 520🔗
trojan://736 .. COM
ss://Y2h .. 866
```

2. As a result, you get 2 files: [all_configs.txt](/results/all_configs.txt) - all working configurations and [fast_configs.txt](/results/fast_configs.txt) - fast working configurations!