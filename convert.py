#!/usr/bin/env python3
"""
Convert v2ray/vless/trojan subscription to Clash config.
Fetches a subscription URL, decodes base64 nodes, and generates a Clash YAML file.
"""

import base64
import json
import sys
import urllib.parse
import urllib.request
import ssl
import yaml
import hashlib


def fetch_subscription(url: str) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "ClashForAndroid/2.5.12"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        data = resp.read()
    try:
        return base64.b64decode(data).decode("utf-8")
    except Exception:
        return data.decode("utf-8", errors="ignore")


def parse_vmess(uri: str) -> dict | None:
    if not uri.startswith("vmess://"):
        return None
    raw = uri[len("vmess://"):]
    try:
        info = json.loads(base64.b64decode(raw + "=="))
    except Exception:
        return None
    proto = info.get("net", "tcp")
    tls = info.get("tls", "") == "tls"
    port = int(info.get("port", 443))
    name = info.get("ps", "") or f"{info.get('add', '')}:{port}"
    proxy = {
        "name": sanitize_name(name),
        "type": "vmess",
        "server": info.get("add", ""),
        "port": port,
        "uuid": info.get("id", ""),
        "alterId": int(info.get("aid", 0)),
        "cipher": info.get("scy", "auto"),
        "network": proto,
    }
    if tls:
        proxy["tls"] = True
        if info.get("sni"):
            proxy["servername"] = info["sni"]
        if info.get("allowInsecure") == "1":
            proxy["skip-cert-verify"] = True
    if proto == "ws":
        ws_opts = {}
        if info.get("path"):
            ws_opts["path"] = info["path"]
        if info.get("host"):
            ws_opts["headers"] = {"Host": info["host"]}
        proxy["ws-opts"] = ws_opts
    elif proto == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": info.get("path", "")}
    return proxy


def parse_vless(uri: str) -> dict | None:
    if not uri.startswith("vless://"):
        return None
    rest = uri[len("vless://"):]
    # vless://uuid@host:port?params#name
    try:
        fragment = rest
        name = ""
        if "#" in fragment:
            fragment, name = fragment.rsplit("#", 1)
            name = urllib.parse.unquote(name)
        query_str = ""
        if "?" in fragment:
            rest2, query_str = fragment.split("?", 1)
        else:
            rest2 = fragment
        uuid, host_port = rest2.split("@", 1)
        if ":" in host_port:
            server, port_str = host_port.rsplit(":", 1)
            port = int(port_str.strip("/"))
        else:
            server = host_port
            port = 443
        params = urllib.parse.parse_qs(query_str)
    except Exception:
        return None

    proto = params.get("type", ["tcp"])[0]
    tls = params.get("security", ["none"])[0]
    name = name or f"{server}:{port}"
    proxy = {
        "name": sanitize_name(name),
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "network": proto,
        "udp": True,
    }
    if tls == "tls":
        proxy["tls"] = True
        sni = params.get("sni", params.get("host", [""]))[0]
        if sni:
            proxy["servername"] = sni
        if params.get("allowInsecure", ["0"])[0] == "1":
            proxy["skip-cert-verify"] = True
        flow = params.get("flow", [""])[0]
        if flow:
            proxy["flow"] = flow
    if proto == "ws":
        proxy["ws-opts"] = {}
        path = params.get("path", [""])[0]
        if path:
            proxy["ws-opts"]["path"] = path
        host = params.get("host", [""])[0]
        if host:
            proxy["ws-opts"]["headers"] = {"Host": host}
    elif proto == "grpc":
        proxy["grpc-opts"] = {
            "grpc-service-name": params.get("serviceName", [""])[0]
        }
    elif proto in ("h2", "http"):
        proxy["h2-opts"] = {}
        path = params.get("path", [""])[0]
        host = params.get("host", [""])[0]
        if path:
            proxy["h2-opts"]["path"] = path
        if host:
            proxy["h2-opts"]["host"] = [host]
    return proxy


def parse_trojan(uri: str) -> dict | None:
    if not uri.startswith("trojan://"):
        return None
    rest = uri[len("trojan://"):]
    name = ""
    if "#" in rest:
        rest, name = rest.rsplit("#", 1)
        name = urllib.parse.unquote(name)
    query_str = ""
    if "?" in rest:
        rest, query_str = rest.split("?", 1)
    # password@host:port
    if "@" in rest:
        password, host_port = rest.split("@", 1)
    else:
        return None
    params = urllib.parse.parse_qs(query_str)
    if ":" in host_port:
        server, port_str = host_port.rsplit(":", 1)
        port = int(port_str.strip("/"))
    else:
        server = host_port
        port = 443
    name = name or f"{server}:{port}"
    proxy = {
        "name": sanitize_name(name),
        "type": "trojan",
        "server": server,
        "port": port,
        "password": password,
        "udp": True,
    }
    sni = params.get("sni", params.get("host", [""]))[0]
    if sni:
        proxy["sni"] = sni
    if params.get("allowInsecure", ["0"])[0] == "1":
        proxy["skip-cert-verify"] = True
    network = params.get("type", ["tcp"])[0]
    if network == "ws":
        proxy["network"] = "ws"
        proxy["ws-opts"] = {}
        path = params.get("path", [""])[0]
        if path:
            proxy["ws-opts"]["path"] = path
        host = params.get("host", [""])[0]
        if host:
            proxy["ws-opts"]["headers"] = {"Host": host}
    elif network == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {
            "grpc-service-name": params.get("serviceName", [""])[0]
        }
    return proxy


def parse_ss(uri: str) -> dict | None:
    if not uri.startswith("ss://"):
        return None
    rest = uri[len("ss://"):]
    name = ""
    if "#" in rest:
        rest, name = rest.rsplit("#", 1)
        name = urllib.parse.unquote(name)
    params = urllib.parse.parse_qs("")
    if "?" in rest:
        rest, query_str = rest.split("?", 1)
        params = urllib.parse.parse_qs(query_str)
    # Try to decode from standard SIP002 format
    try:
        if "@" in rest:
            b64_user, server_port = rest.split("@", 1)
            decoded = base64.b64decode(b64_user + "==").decode()
            method, password = decoded.split(":", 1)
        else:
            decoded = base64.b64decode(rest + "==").decode()
            method, rest2 = decoded.split(":", 1)
            if "@" in rest2:
                password, server_port = rest2.split("@", 1)
            else:
                return None
    except Exception:
        return None
    if ":" in server_port:
        server, port_str = server_port.rsplit(":", 1)
        port = int(port_str.strip("/"))
    else:
        server = server_port
        port = 443
    name = name or f"{server}:{port}"
    return {
        "name": sanitize_name(name),
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
    }


PARSERS = [parse_vmess, parse_vless, parse_trojan, parse_ss]


def sanitize_name(name: str) -> str:
    name = name.strip()
    if not name:
        name = "unnamed"
    bad = ['#', '\\', '\n', '\r']
    for c in bad:
        name = name.replace(c, '')
    if len(name) > 80:
        name = name[:80]
    return name


def deduplicate(proxies: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for p in proxies:
        key = hashlib.md5(json.dumps(p, sort_keys=True).encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            result.append(p)
    return result


CLASH_TEMPLATE = """\
name: "Standard"
mixed-port: 7890
socks-port: 7891
port: 7892
allow-lan: true
bind-address: '*'
mode: global
log-level: info
ipv6: false
external-controller: 127.0.0.1:9090
external-ui: ui
secret: ""
unified-delay: true
tcp-concurrent: true
global-client-fingerprint: chrome
find-process-mode: strict
keep-alive-interval: 15

profile:
  store-selected: true
  store-fake-ip: false

dns:
  enable: true
  ipv6: false
  listen: 0.0.0.0:5353
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.local'
    - '*.lan'
    - '*.localhost'
    - '+.stun.*.*'
    - '+.stun.*.*.*'
    - 'time.*'
    - 'time.*.com'
    - 'connectivitycheck.gstatic.com'
    - 'detectportal.firefox.com'
    - 'captive.apple.com'
    - 'www.msftncsi.com'
    - 'cp.cloudflare.com'
  default-nameserver:
    - 1.1.1.1
    - 1.0.0.1
    - 8.8.8.8
    - 8.8.4.4
    - 9.9.9.9
    - 149.112.112.112
    - 208.67.222.222
    - 208.67.220.220
    - 94.140.14.14
    - 94.140.15.15
    - 64.6.64.6
    - 64.6.65.6
    - 84.200.69.80
    - 84.200.70.40
    - 76.76.19.19
    - 76.223.122.150
    - 8.26.56.26
    - 8.20.247.20
  nameserver:
    - https://cloudflare-dns.com/dns-query
    - https://1.1.1.1/dns-query
    - https://1.0.0.1/dns-query
    - https://dns.google/dns-query
    - https://8.8.8.8/dns-query
    - https://8.8.4.4/dns-query
    - https://dns.quad9.net/dns-query
    - https://9.9.9.9/dns-query
    - https://149.112.112.112/dns-query
    - https://dns.adguard.com/dns-query
    - https://94.140.14.14/dns-query
    - https://94.140.15.15/dns-query
    - https://doh.opendns.com/dns-query
    - https://208.67.222.222/dns-query
    - https://208.67.220.220/dns-query
    - https://doh.comodo.com/dns-query
    - https://8.26.56.26/dns-query
    - https://8.20.247.20/dns-query
    - https://doh.mullvad.net/dns-query
    - https://doh.dns.mullvad.net/dns-query
    - https://freedns.controld.com/p0
    - https://freedns.controld.com/family

proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
      - "Auto"

  - name: "Auto"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 60
    tolerance: 10
    lazy: true
    proxies:
{proxy_names}

rules:
  - MATCH,PROXY
"""


def main():
    if len(sys.argv) < 2:
        print("Usage: python convert.py <subscription_url> [output_file]")
        sys.exit(1)

    url = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "clash.yaml"

    print(f"Fetching subscription from: {url}")
    raw = fetch_subscription(url)

    lines = [line.strip() for line in raw.strip().splitlines() if line.strip()]
    print(f"Found {len(lines)} URI(s)")

    proxies = []
    for line in lines:
        for parser in PARSERS:
            result = parser(line)
            if result:
                proxies.append(result)
                break

    proxies = deduplicate(proxies)
    print(f"Parsed {len(proxies)} unique proxy node(s)")

    if not proxies:
        print("Error: No valid proxy nodes found in subscription")
        sys.exit(1)

    proxy_names = "\n".join(f'      - "{p["name"]}"' for p in proxies)
    clash_content = CLASH_TEMPLATE.replace("{proxy_names}", proxy_names)

    proxies_yaml = yaml.dump({"proxies": proxies}, allow_unicode=True, default_flow_style=False, sort_keys=False)
    # Insert proxies block
    clash_content = clash_content.replace(
        "\nproxy-groups:",
        f"\n{proxies_yaml}\nproxy-groups:"
    )

    with open(output, "w", encoding="utf-8") as f:
        f.write(clash_content)

    print(f"Clash config written to: {output}")

    # Write node count for workflow
    with open("node_count.txt", "w") as f:
        f.write(str(len(proxies)))


if __name__ == "__main__":
    main()
