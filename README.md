# asn-prefix-hunter
CLI tool that pulls current and historical IPv4/IPv6 prefixes for any ASN and tells you which network is announcing “lost” address space today.


# asn-prefix-hunter

`asn-prefix-hunter` is a single-file Python 3 CLI that helps network-security
and OSINT practitioners answer two questions:

1. **What IP prefixes does this ASN announce right now?**
2. **If an ASN went dark, who is announcing its old blocks today?**

It queries free public APIs (RIPE NCC, BGPView, IPinfo) and falls back to
historical data so you never get an empty result.

---

## Features

* **Live + Historic prefixes** – RIPEstat `announced-prefixes` API with `lod=2`.
* **Successor detection** –  
   ‐ RIPE DB `origin:` lookup  
   ‐ Per-prefix origin via RIPEstat → BGPView → IPinfo  
   ‐ Tunable sample size (`--sample`, `--debug`).
* **Graceful fallback** – if an ASN no longer appears in BGP, its historic
  space is still returned.
* **Exports** – CSV or JSON, or stream to stdout for shell pipes.
* **Unicode-robust CLI** – commas, spaces, non-breaking spaces all parse.

---

## Quick start

```bash
# install deps
python3 -m pip install requests tqdm

# get current + historic prefixes for five ASNs
python get_asn_prefixes.py AS45025,42430,43554,24881,47598 --history

# hunt for who now holds silent Ukrainian ASNs (verbose)
python get_asn_prefixes.py \
    --token YOUR_IPINFO_TOKEN \
    AS45025,42430 --history --sample 0 --debug

