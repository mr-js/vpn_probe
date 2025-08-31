# vpn_probe
Probe all your vpn-configs for **xray** in one click [async]

![vpn_probe](/images/vpn_probe.png)

## Features

Support ready configs for Nekoray (xray):

✅ vmess
✅ vless
✅ trojan
✅ ss

Lightweight, async and cross platform console app!


## Setup

1. Install **xray**:

```
# xray setup (for MacOS):
brew install xray 
```

## Usage

1. Place in the **[/input](/input/)** folder txt-files with vpn-configs, for example:

```
# test.txt:
vmess://eyJ .. Q==
vless://e7c .. 520🔗
trojan://736 .. COM
ss://Y2h .. 866
```

2. Run **[app.py](/app.py)**.

3. As a result, in the **[/results](/results/)** folder you get 2 files: **[all_configs.txt](/results/all_configs.txt)** - all working configurations and **[fast_configs.txt](/results/fast_configs.txt)** - fast working configurations!

PS: You can set the default values for the required parameters in **[app.toml](/app.toml)**.