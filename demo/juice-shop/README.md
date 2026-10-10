# Demo: scan, fix, rescan

A reproducible fix-and-rescan loop against OWASP Juice Shop, run entirely on your
own machine so it does not depend on anyone's uptime.

Juice Shop is deliberately vulnerable and we do not patch it. The fix goes in
front of it, which is the remediation PatchPilot recommends whenever a finding
cannot be fixed in the application itself.

## 1 - Start the target, unprotected

```bash
docker run -d --name juiceshop -p 8080:3000 bkimminich/juice-shop
```

Port **8080** matters: `url_guard` only permits 80, 443, 8080 and 8443.

## 2 - Scan it

Set `ALLOW_PRIVATE_TARGETS=true` in `backend/.env`, then scan `http://localhost:8080/`.

```
[HIGH  ] Site served over plain HTTP - all traffic is unencrypted
[HIGH  ] Missing security header: Content-Security-Policy
[HIGH  ] Directory listing exposed: /ftp
[MEDIUM] Prometheus metrics exposed publicly (internal telemetry): /metrics
[LOW   ] Missing security header: Referrer-Policy
[LOW   ] Missing security header: Permissions-Policy
[LOW   ] Wildcard CORS policy on public content

Risk score: 74/100 HIGH
```

Open `http://localhost:8080/ftp` in a browser. `acquisitions.md` inside it opens
with *"This document is confidential"*. The finding is real.

> **Your run will show more findings than this, and that is expected.** The
> listings here are the website portion. Scanning `localhost` also port scans
> **your own machine**, so whatever you happen to be running appears too. On the
> machine this was last verified on, three loopback findings were added:
> PostgreSQL on 5432, DNS on 53, and the demo's own 8080.
>
> They are graded as what they are. PostgreSQL comes out MEDIUM, not the CRITICAL
> a public database would score, and the text says why: *"listening on this
> machine's loopback interface... it is not reachable from the network."* Point at
> that during the demo. A scanner that called your laptop's database an internet
> exposure would be easy to write and worth nothing.

## 3 - Fix it at the edge

Move Juice Shop off the host port and put nginx in front of it:

```bash
docker rm -f juiceshop
docker network create juicenet
docker run -d --name juiceshop --network juicenet bkimminich/juice-shop
docker build -t juice-edge demo/juice-shop
docker run -d --name juice-edge --network juicenet -p 8080:8080 juice-edge
```

`nginx.conf` adds the three missing headers, drops the wildcard CORS header, and
returns 403 for `/ftp` and `/metrics`.

## 4 - Rescan

```
[HIGH  ] Site served over plain HTTP - all traffic is unencrypted

Risk score: 40/100 MEDIUM
```

Seven website findings to one. Same scan, same scoring, nothing edited in the
report. The loopback findings from step 2 are still there and still unchanged,
because nothing about your own machine was fixed: verified end to end on
2026-08-22, the full report reads **4 findings, 40/100 MEDIUM**.

**The interesting part happened between passes.** The first hardening attempt
scored 40/100 but reported a *new* finding - `Server information disclosed via
'server': nginx/1.31.3` - because the proxy advertised its own version. The fix
introduced it and the rescan caught it. `server_tokens off` closes it.

The remaining HIGH is honest: the site really is served over plain HTTP. In
production you terminate TLS at this same edge with a real certificate. A
self-signed certificate would trade this finding for a CRITICAL one, which is
the scanner behaving correctly.

## Clean up

```bash
docker rm -f juiceshop juice-edge
docker network rm juicenet
```
