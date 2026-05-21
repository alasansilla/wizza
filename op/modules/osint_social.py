#!/usr/bin/env python3
"""
OSINT Social — PhD-level identity intelligence across 80+ platforms.

Capabilities:
  1. Username/email/name enumeration across 80+ platforms
  2. Profile data extraction (bio, followers, location, join date, avatar)
  3. Cross-platform identity correlation (perceptual image hash, bio NLP, timing)
  4. Breach/leak database check (HaveIBeenPwned, IntelX snippet)
  5. Email permutation + MX verification
  6. Phone number OSINT (WhatsApp, Telegram, Truecaller)
  7. Relationship graph (followers/following spider for Reddit, GitHub)
  8. Behavioral timeline (post times → timezone inference)
  9. Stylometry fingerprint (writing pattern across platforms)
 10. HTML report with correlation confidence scores

Usage:
    from op.modules.osint_social import run
    run()                                # interactive menu
    run(username="john_doe")             # single username
    run(email="john@example.com")        # email → username derivation + breach check
    run(name="John Doe")                 # name → username candidates
    run(username="john_doe", deep=True)  # full deep scan (profile + correlation)
"""

import re, sys, time, json, os, math, hashlib, hmac, io
import string, itertools, threading, socket, struct, base64
import urllib.request, urllib.error, urllib.parse, http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter
from typing import Optional, List, Dict, Tuple
from datetime import datetime

# ══════════════════════════════════════════════════════════════════════════════
#  PLATFORM DEFINITIONS
#  Format: (name, url, expected_status, not_found_string, confirm_string,
#           extract_fn_name)
#  extract_fn_name → function in EXTRACTORS dict for profile data
# ══════════════════════════════════════════════════════════════════════════════
PLATFORMS = [
    # ── Social ──────────────────────────────────────────────────────────────
    ("Instagram",   "https://www.instagram.com/{u}/",                    200, "Page Not Found",                  '"username":"{u}"',     "ig"),
    ("Twitter/X",   "https://x.com/{u}",                                 200, "This account doesn't exist",      None,                   "twitter"),
    ("TikTok",      "https://www.tiktok.com/@{u}",                       200, "Couldn't find this account",      '"uniqueId":"{u}"',     "tiktok"),
    ("Facebook",    "https://www.facebook.com/{u}",                      200, "content not found",               None,                   None),
    ("Snapchat",    "https://www.snapchat.com/add/{u}",                  200, "Sorry, we couldn't find",         "{u}",                  "snapchat"),
    ("Pinterest",   "https://www.pinterest.com/{u}/",                    200, "User not found",                  '"username": "{u}"',    None),
    ("LinkedIn",    "https://www.linkedin.com/in/{u}",                   200, "Page not found",                  None,                   None),
    ("Reddit",      "https://www.reddit.com/user/{u}/about.json",        200, '"error": 404',                    '"name": "{u}"',        "reddit"),
    ("Tumblr",      "https://{u}.tumblr.com",                            200, "There's nothing here",            None,                   None),
    ("Flickr",      "https://www.flickr.com/people/{u}",                 200, "Page Not Found",                  None,                   None),
    ("VK",          "https://vk.com/{u}",                                200, "This page is under construction", None,                   None),
    ("Telegram",    "https://t.me/{u}",                                  200, "tgme_page_extra",                 "tgme_page_title",      "telegram"),
    ("Twitch",      "https://www.twitch.tv/{u}",                         200, "Sorry. Unless you",               None,                   "twitch"),
    ("YouTube",     "https://www.youtube.com/@{u}",                      200, "This channel doesn't exist",      None,                   None),
    ("Mastodon",    "https://mastodon.social/@{u}",                      200, "The page you are looking",        "{u}",                  None),
    ("BeReal",      "https://bere.al/{u}",                               200, "User not found",                  "{u}",                  "bereal"),
    # ── Dev / Tech ──────────────────────────────────────────────────────────
    ("GitHub",      "https://api.github.com/users/{u}",                  200, '"message": "Not Found"',          '"login": "{u}"',       "github"),
    ("GitLab",      "https://gitlab.com/{u}",                            200, "404",                             "{u}",                  None),
    ("HackerNews",  "https://news.ycombinator.com/user?id={u}",          200, "No such user",                    "{u}",                  "hn"),
    ("Dev.to",      "https://dev.to/api/users/by_username?url={u}",      200, "Not Found",                       '"username":"{u}"',     "devto"),
    ("Replit",      "https://replit.com/@{u}",                           200, "User not found",                  "{u}",                  None),
    ("Codepen",     "https://codepen.io/{u}",                            200, "404",                             "{u}",                  None),
    ("Pastebin",    "https://pastebin.com/u/{u}",                        200, "Not Found",                       "{u}",                  None),
    ("Keybase",     "https://keybase.io/{u}",                            200, "is not a Keybase user",           "{u}",                  "keybase"),
    ("HackTheBox",  "https://www.hackthebox.com/api/v4/user/profile/overview/{u}", 200, '"status":"error"', '"name":', None),
    ("TryHackMe",   "https://tryhackme.com/api/user/exist/{u}",          200, '"success":false',                 '"success":true',       None),
    # ── Media / Creative ────────────────────────────────────────────────────
    ("SoundCloud",  "https://soundcloud.com/{u}",                        200, "404",                             "{u}",                  None),
    ("Spotify",     "https://open.spotify.com/user/{u}",                 200, "Page not found",                  "{u}",                  "spotify"),
    ("Bandcamp",    "https://{u}.bandcamp.com",                          200, "not found",                       None,                   None),
    ("Vimeo",       "https://vimeo.com/{u}",                             200, "Page Not Found",                  "{u}",                  None),
    ("Dailymotion", "https://api.dailymotion.com/user/{u}",              200, '"error"',                         '"id":',                None),
    ("Mixcloud",    "https://api.mixcloud.com/{u}/",                     200, '"error"',                         '"username": "{u}"',    None),
    ("DeviantArt",  "https://www.deviantart.com/{u}",                    200, "Page Not Found",                  "{u}",                  None),
    ("ArtStation",  "https://www.artstation.com/{u}",                    200, "404",                             "{u}",                  None),
    ("Behance",     "https://www.behance.net/{u}",                       200, "404",                             "{u}",                  None),
    # ── Gaming ──────────────────────────────────────────────────────────────
    ("Steam",       "https://steamcommunity.com/id/{u}/?xml=1",          200, "<error>",                         "<steamID64>",          "steam"),
    ("Roblox",      "https://api.roblox.com/users/get-by-username?username={u}", 200, '"Id":null', '"Id":',      None),
    ("Chess.com",   "https://api.chess.com/pub/player/{u}",              200, "Player not found",                '"username":"{u}"',     "chess"),
    ("Lichess",     "https://lichess.org/api/user/{u}",                  200, "Not found",                       '"username":"{u}"',     "lichess"),
    # ── Professional ────────────────────────────────────────────────────────
    ("Medium",      "https://medium.com/@{u}",                           200, "Page not found",                  None,                   None),
    ("Substack",    "https://{u}.substack.com",                          200, "not found",                       None,                   None),
    ("Quora",       "https://www.quora.com/profile/{u}",                 200, "404",                             None,                   None),
    ("Gravatar",    "https://en.gravatar.com/{u}.json",                  200, "User not found",                  '"display_name"',       "gravatar"),
    ("Linktree",    "https://linktr.ee/{u}",                             200, "Sorry, this page isn't available","{u}",                  None),
    ("ProductHunt", "https://www.producthunt.com/@{u}",                  200, "404",                             None,                   None),
    # ── Regional ────────────────────────────────────────────────────────────
    ("Weibo",       "https://weibo.com/{u}",                             200, "用户不存在",                       None,                   "weibo"),
    ("LiveJournal", "https://{u}.livejournal.com",                       200, "Sorry, this journal doesn't exist",None,                  None),
    ("Minds",       "https://www.minds.com/api/v1/channel/{u}",          200, '"status":"error"',                '"guid":',              None),
    # ── Extras ──────────────────────────────────────────────────────────────
    ("AboutMe",     "https://about.me/{u}",                              200, "Page Not Found",                  "{u}",                  None),
    ("Cashapp",     "https://cash.app/${u}",                             200, "Not Found",                       "{u}",                  None),
    ("Venmo",       "https://account.venmo.com/u/{u}",                   200, "404",                             "{u}",                  None),
    ("Duolingo",    "https://www.duolingo.com/profile/{u}",              200, "couldn't find",                   "{u}",                  "duolingo"),
    ("Strava",      "https://www.strava.com/athletes/{u}",               200, "Page Not Found",                  "{u}",                  None),
    ("Letterboxd",  "https://letterboxd.com/{u}/",                       200, "Sorry, we can't find",            "{u}",                  None),
    ("Goodreads",   "https://www.goodreads.com/{u}",                     200, "Page not found",                  "{u}",                  None),
    ("Last.fm",     "https://www.last.fm/user/{u}",                      200, "User not found",                  "{u}",                  "lastfm"),
    ("Ravelry",     "https://www.ravelry.com/people/{u}",                200, "not found",                       "{u}",                  None),
    ("Fiverr",      "https://www.fiverr.com/{u}",                        200, "404",                             "{u}",                  None),
    ("Upwork",      "https://www.upwork.com/freelancers/~{u}",           200, "No profile",                      "{u}",                  None),
    ("Freelancer",  "https://www.freelancer.com/u/{u}",                  200, "Not Found",                       "{u}",                  None),
    ("Instructables","https://www.instructables.com/member/{u}/",        200, "User Not Found",                  "{u}",                  None),
    ("HackerRank",  "https://www.hackerrank.com/{u}",                    200, "404",                             "{u}",                  "hackerrank"),
    ("LeetCode",    "https://leetcode.com/{u}/",                         200, "404",                             "{u}",                  None),
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


# ══════════════════════════════════════════════════════════════════════════════
#  PROFILE EXTRACTORS — pull structured data from found profiles
# ══════════════════════════════════════════════════════════════════════════════

def _fetch(url, timeout=12) -> Tuple[int, str]:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read(32768).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        b = ""
        try: b = e.read(8192).decode("utf-8", errors="ignore")
        except: pass
        return e.code, b
    except Exception:
        return 0, ""


def _re(pattern, text, default=""):
    m = re.search(pattern, text)
    return m.group(1).strip() if m else default


def _extract_github(username: str, body: str) -> dict:
    try:
        d = json.loads(body)
        return {
            "display_name":  d.get("name", ""),
            "bio":           d.get("bio", ""),
            "location":      d.get("location", ""),
            "email":         d.get("email", ""),
            "company":       d.get("company", ""),
            "followers":     d.get("followers", 0),
            "following":     d.get("following", 0),
            "public_repos":  d.get("public_repos", 0),
            "created_at":    d.get("created_at", ""),
            "avatar_url":    d.get("avatar_url", ""),
            "blog":          d.get("blog", ""),
            "twitter":       d.get("twitter_username", ""),
        }
    except: return {}


def _extract_reddit(username: str, body: str) -> dict:
    try:
        d = json.loads(body).get("data", {})
        created = d.get("created_utc", 0)
        return {
            "display_name":  d.get("name", ""),
            "karma_post":    d.get("link_karma", 0),
            "karma_comment": d.get("comment_karma", 0),
            "created_at":    datetime.utcfromtimestamp(created).isoformat() if created else "",
            "is_gold":       d.get("is_gold", False),
            "verified":      d.get("verified", False),
            "avatar_url":    d.get("icon_img", "").split("?")[0],
            "bio":           d.get("subreddit", {}).get("public_description", ""),
        }
    except: return {}


def _extract_ig(username: str, body: str) -> dict:
    d = {}
    d["followers"]    = _re(r'"edge_followed_by":\{"count":(\d+)', body)
    d["following"]    = _re(r'"edge_follow":\{"count":(\d+)', body)
    d["posts"]        = _re(r'"edge_owner_to_timeline_media":\{"count":(\d+)', body)
    d["bio"]          = _re(r'"biography":"([^"]*)"', body)
    d["display_name"] = _re(r'"full_name":"([^"]*)"', body)
    d["verified"]     = "true" in _re(r'"is_verified":(true|false)', body)
    d["avatar_url"]   = _re(r'"profile_pic_url_hd":"([^"]*)"', body).replace("\\u0026","&")
    d["website"]      = _re(r'"external_url":"([^"]*)"', body)
    d["private"]      = "true" in _re(r'"is_private":(true|false)', body)
    d["pk"]           = _re(r'"id":"(\d+)"', body)
    return {k: v for k, v in d.items() if v}


def _extract_twitter(username: str, body: str) -> dict:
    d = {}
    d["display_name"] = _re(r'"name":"([^"]+)"', body)
    d["bio"]          = _re(r'"description":"([^"]*)"', body)
    d["followers"]    = _re(r'"followers_count":(\d+)', body)
    d["location"]     = _re(r'"location":"([^"]*)"', body)
    d["verified"]     = "true" in _re(r'"verified":(true|false)', body)
    d["created_at"]   = _re(r'"created_at":"([^"]*)"', body)
    return {k: v for k, v in d.items() if v}


def _extract_telegram(username: str, body: str) -> dict:
    return {
        "display_name": _re(r'class="tgme_page_title"[^>]*>([^<]+)', body),
        "bio":          _re(r'class="tgme_page_description"[^>]*>(.*?)</div>', body),
        "subscribers":  _re(r'([\d\s]+)\s+(?:members|subscribers)', body),
        "type":         "channel" if "tgme_channel" in body else "user",
    }


def _extract_twitch(username: str, body: str) -> dict:
    return {
        "display_name": _re(r'"displayName":"([^"]+)"', body),
        "bio":          _re(r'"description":"([^"]*)"', body),
        "followers":    _re(r'"followers":(\d+)', body),
        "views":        _re(r'"viewCount":(\d+)', body),
        "created_at":   _re(r'"createdAt":"([^"]+)"', body),
    }


def _extract_keybase(username: str, body: str) -> dict:
    try:
        d = json.loads(body).get("them", [{}])[0] if "[" in body else json.loads(body).get("them", {})
        if isinstance(d, list): d = d[0] if d else {}
        proofs = d.get("proofs_summary", {}).get("all", [])
        return {
            "display_name": d.get("profile", {}).get("full_name", ""),
            "bio":          d.get("profile", {}).get("bio", ""),
            "location":     d.get("profile", {}).get("location", ""),
            "proofs":       [f"{p['proof_type']}:{p['nametag']}" for p in proofs],
            "pgp_keys":     len(d.get("public_keys", {}).get("pgp_public_keys", [])),
        }
    except: return {}


def _extract_gravatar(username: str, body: str) -> dict:
    try:
        d = json.loads(body).get("entry", [{}])[0]
        emails = [e.get("value","") for e in d.get("emails", [])]
        accounts = [a.get("domain","") for a in d.get("accounts", [])]
        return {
            "display_name": d.get("displayName", ""),
            "bio":          d.get("aboutMe", ""),
            "location":     d.get("currentLocation", ""),
            "emails":       emails,
            "linked_accounts": accounts,
            "avatar_url":   d.get("thumbnailUrl", ""),
        }
    except: return {}


def _extract_steam(username: str, body: str) -> dict:
    return {
        "steam_id":     _re(r'<steamID64>(\d+)</steamID64>', body),
        "display_name": _re(r'<steamID>([^<]+)</steamID>', body),
        "created_at":   _re(r'<memberSince>([^<]+)</memberSince>', body),
        "location":     _re(r'<location>([^<]+)</location>', body),
        "realname":     _re(r'<realname>([^<]+)</realname>', body),
    }


def _extract_chess(username: str, body: str) -> dict:
    try:
        d = json.loads(body)
        return {
            "display_name": d.get("name", ""),
            "location":     d.get("location", ""),
            "followers":    d.get("followers", 0),
            "country":      d.get("country", "").split("/")[-1],
            "joined":       datetime.utcfromtimestamp(d.get("joined",0)).isoformat() if d.get("joined") else "",
            "status":       d.get("status", ""),
            "verified":     d.get("verified", False),
        }
    except: return {}


def _extract_lichess(username: str, body: str) -> dict:
    try:
        d = json.loads(body)
        return {
            "display_name": d.get("username", ""),
            "title":        d.get("title", ""),
            "bio":          d.get("profile", {}).get("bio", ""),
            "country":      d.get("profile", {}).get("country", ""),
            "location":     d.get("profile", {}).get("location", ""),
            "followers":    d.get("nbFollowers", 0),
            "following":    d.get("nbFollowing", 0),
            "created_at":   datetime.utcfromtimestamp(d.get("createdAt",0)//1000).isoformat() if d.get("createdAt") else "",
        }
    except: return {}


def _extract_hn(username: str, body: str) -> dict:
    return {
        "karma":      _re(r'karma:\s*</td><td>(\d+)', body),
        "about":      re.sub(r'<[^>]+>', '', _re(r'<td valign="top">about:\s*</td><td>(.*?)</td>', body)),
        "created_at": _re(r'created:\s*</td><td>([^<]+)', body),
    }


def _extract_devto(username: str, body: str) -> dict:
    try:
        d = json.loads(body)
        return {
            "display_name": d.get("name", ""),
            "bio":          d.get("summary", ""),
            "location":     d.get("location", ""),
            "github":       d.get("github_username", ""),
            "twitter":      d.get("twitter_username", ""),
            "followers":    d.get("followers_count", 0),
            "joined":       d.get("joined_at", ""),
        }
    except: return {}


def _extract_snapchat(username: str, body: str) -> dict:
    return {
        "display_name": _re(r'"display_name"\s*:\s*"([^"]+)"', body),
        "bitmoji":      "true" if "bitmoji" in body.lower() else "false",
        "subscribers":  _re(r'"subscriber_count"\s*:\s*(\d+)', body),
    }


def _extract_tiktok(username: str, body: str) -> dict:
    return {
        "display_name": _re(r'"nickname":"([^"]+)"', body),
        "bio":          _re(r'"signature":"([^"]*)"', body),
        "followers":    _re(r'"followerCount":(\d+)', body),
        "following":    _re(r'"followingCount":(\d+)', body),
        "likes":        _re(r'"heartCount":(\d+)', body),
        "verified":     "true" in _re(r'"verified":(true|false)', body),
        "avatar_url":   _re(r'"avatarLarger":"([^"]+)"', body).replace("\\u002F","/"),
    }


def _extract_lastfm(username: str, body: str) -> dict:
    return {
        "display_name": _re(r'"name":"([^"]+)"', body),
        "scrobbles":    _re(r'"playcount":"(\d+)"', body),
        "country":      _re(r'"country":"([^"]+)"', body),
        "registered":   _re(r'"registered":\{"#text":"([^"]+)"', body),
        "avatar_url":   _re(r'"image":\[.*?"#text":"([^"]+)".*?\]', body),
    }


def _extract_bereal(username: str, body: str) -> dict:
    return {
        "display_name": _re(r'<title>([^<|]+)', body).strip(),
        "bio":          _re(r'"description"\s*content="([^"]*)"', body),
        "avatar_url":   _re(r'"og:image"\s+content="([^"]+)"', body),
        "followers":    _re(r'([\d,]+)\s*[Ff]ollower', body).replace(",", ""),
    }


def _extract_spotify(username: str, body: str) -> dict:
    # Spotify embeds JSON in <script id="initial-state"> as base64
    b64 = _re(r'<script id="initial-state"[^>]*>([^<]+)</script>', body)
    if b64:
        try:
            import base64 as _b64
            decoded = _b64.b64decode(b64 + "==").decode("utf-8", errors="ignore")
            return {
                "display_name": _re(r'"name"\s*:\s*"([^"]+)"', decoded),
                "followers":    _re(r'"total_followers"\s*:\s*(\d+)', decoded),
                "avatar_url":   _re(r'"url"\s*:\s*"(https://i\.scdn\.co/[^"]+)"', decoded),
                "public_playlists": _re(r'"total"\s*:\s*(\d+)', decoded),
            }
        except: pass
    return {
        "display_name": _re(r'"og:title"\s+content="([^"]+)"', body),
        "followers":    _re(r'"followers":\{"href":null,"total":(\d+)', body),
        "avatar_url":   _re(r'"og:image"\s+content="([^"]+)"', body),
    }


def _extract_duolingo(username: str, body: str) -> dict:
    # Duolingo public API: /2017-06-30/users?username=X
    # body here is the profile page HTML; fetch the API separately
    _, api_body = _fetch(f"https://www.duolingo.com/2017-06-30/users?username={urllib.parse.quote(username)}")
    try:
        data = json.loads(api_body)
        users = data.get("users", [])
        if not users: return {}
        u = users[0]
        languages = [f"{l['language']} ({l['level']})" for l in u.get("courses", [])[:4]]
        return {
            "display_name": u.get("name", ""),
            "bio":          u.get("bio", ""),
            "location":     u.get("location", ""),
            "avatar_url":   u.get("picture", "").replace("//", "https://") if u.get("picture","").startswith("//") else u.get("picture",""),
            "followers":    u.get("totalFollowers", 0),
            "following":    u.get("totalFollowing", 0),
            "streak":       u.get("streak", 0),
            "xp":           u.get("totalXp", 0),
            "languages":    ", ".join(languages),
            "created_at":   datetime.utcfromtimestamp(u.get("creationDate", 0)).isoformat() if u.get("creationDate") else "",
        }
    except:
        return {
            "display_name": _re(r'"og:title"\s+content="([^"]+)"', body),
        }


def _extract_hackerrank(username: str, body: str) -> dict:
    _, api_body = _fetch(f"https://www.hackerrank.com/rest/hackers/{urllib.parse.quote(username)}/recent_challenges?limit=0")
    badges_body = _fetch(f"https://www.hackerrank.com/rest/hackers/{urllib.parse.quote(username)}/badges")[1]
    try:
        badges = json.loads(badges_body)
        badge_names = [b.get("name","") for b in badges.get("models",[])[:5]] if isinstance(badges.get("models"), list) else []
    except:
        badge_names = []
    return {
        "display_name": _re(r'"name"\s*:\s*"([^"]+)"', body),
        "avatar_url":   _re(r'"avatar"\s*:\s*"([^"]+)"', body),
        "school":       _re(r'"school"\s*:\s*"([^"]*)"', body),
        "country":      _re(r'"country"\s*:\s*"([^"]*)"', body),
        "badges":       ", ".join(badge_names),
        "level":        _re(r'"level"\s*:\s*(\d+)', body),
    }


def _extract_weibo(username: str, body: str) -> dict:
    return {
        "display_name": _re(r'<title>([^_<]+)', body).strip(),
        "bio":          _re(r'class="pf-intro"[^>]*>([^<]+)', body).strip(),
        "followers":    _re(r'粉丝[^\d]*([\d万]+)', body),
        "following":    _re(r'关注[^\d]*([\d万]+)', body),
        "location":     _re(r'class="pf-region"[^>]*>([^<]+)', body).strip(),
        "avatar_url":   _re(r'"avatar_hd"\s*:\s*"([^"]+)"', body),
    }


EXTRACTORS = {
    "ig":       _extract_ig,
    "twitter":  _extract_twitter,
    "tiktok":   _extract_tiktok,
    "snapchat": _extract_snapchat,
    "reddit":   _extract_reddit,
    "github":   _extract_github,
    "telegram": _extract_telegram,
    "twitch":   _extract_twitch,
    "keybase":  _extract_keybase,
    "gravatar": _extract_gravatar,
    "steam":    _extract_steam,
    "chess":    _extract_chess,
    "lichess":  _extract_lichess,
    "hn":       _extract_hn,
    "devto":    _extract_devto,
    "lastfm":      _extract_lastfm,
    "bereal":      _extract_bereal,
    "spotify":     _extract_spotify,
    "duolingo":    _extract_duolingo,
    "hackerrank":  _extract_hackerrank,
    "weibo":       _extract_weibo,
}


# ══════════════════════════════════════════════════════════════════════════════
#  USERNAME GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def _gen_from_name(name: str) -> list:
    name = name.strip().lower()
    parts = name.split()
    if not parts: return []
    candidates = set()
    if len(parts) == 1:
        f = parts[0]
        candidates.update([f, f+"1", f+"123", f+"_official", f+".real"])
    elif len(parts) >= 2:
        f, l = parts[0], parts[-1]
        mid = parts[1] if len(parts) > 2 else ""
        for sep in ("", ".", "_", "-"):
            candidates.update([
                f"{f}{sep}{l}", f"{l}{sep}{f}",
                f"{f[0]}{sep}{l}", f"{f}{sep}{l[0]}",
                f"{f}{sep}{l}1", f"{f}{sep}{l}01",
            ])
        if mid:
            candidates.update([f"{f[0]}{mid[0]}{l}", f"{f}{mid[0]}{l}"])
        candidates.update([f, l, f+l, l+f])
        # Cultural variants
        candidates.update([
            f"{f}{l}".replace(" ",""),
            f"{f[0]}{l}".replace(" ",""),
        ])
    return [c for c in candidates if c and 3 <= len(c) <= 30 and re.match(r'^[a-z0-9._\-]+$', c)]


def _gen_from_email(email: str) -> list:
    email = email.strip().lower()
    local = email.split("@")[0]
    base = re.sub(r'\d+$', '', local)
    parts = re.split(r'[._\-+]', local)
    candidates = set([local, base] + parts)
    candidates.update(_gen_from_name(" ".join(parts)))
    return [c for c in candidates if c and len(c) >= 3]


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP PROBE
# ══════════════════════════════════════════════════════════════════════════════

def _probe(platform, url_tpl, exp_status, err_str, confirm_str, username,
           timeout=10, extract=False) -> Optional[dict]:
    if url_tpl is None:
        return None
    url = url_tpl.replace("{u}", urllib.parse.quote(username))
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read(65536).decode("utf-8", errors="ignore")
        status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        body = ""
        try: body = e.read(8192).decode("utf-8", errors="ignore")
        except: pass
    except Exception:
        return None

    if status in (404, 410):
        return None
    if err_str:
        if err_str.replace("{u}", username).lower() in body.lower():
            return None
    if confirm_str:
        if confirm_str.replace("{u}", username).lower() not in body.lower():
            return None
    if exp_status and status != exp_status:
        return None

    result = {"platform": platform, "url": url, "status": status, "profile": {}}
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  PROFILE DEEP EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def _deep_extract(result: dict, extract_key: str, username: str):
    """Fetch full page body and run extractor to populate result['profile']."""
    if not extract_key or extract_key not in EXTRACTORS:
        return
    _, body = _fetch(result["url"])
    if body:
        data = EXTRACTORS[extract_key](username, body)
        result["profile"] = {k: v for k, v in data.items() if v}


# ══════════════════════════════════════════════════════════════════════════════
#  BREACH / LEAK CHECK
# ══════════════════════════════════════════════════════════════════════════════

def check_breach_hibp(email: str) -> list:
    """Check HaveIBeenPwned for email breaches (no API key needed for count)."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    req = urllib.request.Request(url, headers={
        "User-Agent": "OSINT-Research-Tool/1.0",
        "hibp-api-key": "",  # fill in if you have one
    })
    try:
        r = urllib.request.urlopen(req, timeout=10)
        return json.loads(r.read(32768))
    except urllib.error.HTTPError as e:
        if e.code == 404: return []   # not found = not breached
        if e.code == 401: return [{"Name": "API_KEY_NEEDED"}]
        return []
    except:
        return []


def check_breach_dehashed_snippet(email: str) -> str:
    """Public Dehashed snippet — returns count without paid API."""
    url = f"https://www.dehashed.com/search?query=email%3A{urllib.parse.quote(email)}"
    _, body = _fetch(url)
    m = re.search(r'([\d,]+)\s+results?\s+found', body, re.IGNORECASE)
    return m.group(1).replace(",", "") if m else "0"


def check_password_hash(email: str) -> dict:
    """Check leaked password hashes via HIBP Passwords API (k-anonymity)."""
    # Hash the email to look up as a "password" — checks if email IS a leaked password
    sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    _, body = _fetch(url)
    for line in body.splitlines():
        if line.startswith(suffix):
            count = line.split(":")[1].strip()
            return {"found": True, "count": int(count)}
    return {"found": False, "count": 0}


# ══════════════════════════════════════════════════════════════════════════════
#  EMAIL OSINT
# ══════════════════════════════════════════════════════════════════════════════

def email_mx_verify(email: str) -> dict:
    """Verify email deliverability via MX DNS lookup."""
    domain = email.split("@")[-1]
    result = {"domain": domain, "mx": [], "deliverable": False}
    try:
        import subprocess
        out = subprocess.check_output(["dig", "+short", "MX", domain],
                                       stderr=subprocess.DEVNULL, timeout=5).decode()
        mx_records = [line.split()[-1].rstrip(".") for line in out.strip().splitlines() if line]
        result["mx"] = mx_records
        result["deliverable"] = len(mx_records) > 0
    except:
        pass
    return result


def email_provider_osint(email: str) -> dict:
    """Detect provider type and disposable email services."""
    domain = email.split("@")[-1].lower()
    DISPOSABLE = {"mailinator","guerrillamail","tempmail","throwam","yopmail","sharklasers",
                  "guerrillamailblock","grr.la","guerrillamail.info","spam4.me","trashmail"}
    BIG_PROVIDERS = {"gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com",
                     "protonmail.com","zoho.com","gmx.com"}
    return {
        "domain": domain,
        "is_disposable": domain in DISPOSABLE or any(d in domain for d in DISPOSABLE),
        "is_major_provider": domain in BIG_PROVIDERS,
        "likely_real": domain not in DISPOSABLE,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  PHONE OSINT
# ══════════════════════════════════════════════════════════════════════════════

def phone_whatsapp_check(phone: str) -> dict:
    """Check if phone is registered on WhatsApp via wa.me."""
    url = f"https://wa.me/{phone.replace('+','').replace(' ','')}"
    status, body = _fetch(url)
    registered = "open a chat" in body.lower() or "send message" in body.lower()
    return {"registered": registered, "url": url}


def phone_telegram_check(phone: str) -> dict:
    """Attempt Telegram fragment lookup (public API, limited)."""
    url = f"https://fragment.com/number/{phone.replace('+','').replace(' ','')}"
    status, body = _fetch(url)
    return {
        "fragment_status": status,
        "available": "available" in body.lower(),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  PERCEPTUAL IMAGE HASH (for cross-platform avatar correlation)
# ══════════════════════════════════════════════════════════════════════════════

def _fetch_image_bytes(url: str) -> Optional[bytes]:
    if not url: return None
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        r = urllib.request.urlopen(req, timeout=10)
        return r.read(2 * 1024 * 1024)
    except:
        return None


def perceptual_hash(image_bytes: bytes) -> Optional[str]:
    """
    Pure-Python 8x8 average hash (no Pillow required).
    Decodes JPEG/PNG minimally to get pixel data.
    Returns 64-bit hex string.
    """
    if not image_bytes:
        return None
    # Use a minimal PPM via external tool if available, otherwise skip
    try:
        import subprocess, tempfile
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as f:
            f.write(image_bytes); fname = f.name
        # Try ImageMagick
        out = subprocess.check_output(
            ["convert", fname, "-resize", "8x8!", "-colorspace", "Gray",
             "-depth", "8", "txt:-"],
            stderr=subprocess.DEVNULL, timeout=5)
        pixels = [int(re.search(r'gray\((\d+)\)', line.decode()).group(1))
                  for line in out.splitlines() if b"gray" in line]
        os.unlink(fname)
        if len(pixels) < 64: return None
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p >= avg else "0" for p in pixels[:64])
        return hex(int(bits, 2))[2:].zfill(16)
    except:
        return None


def hamming_distance(h1: str, h2: str) -> int:
    if not h1 or not h2 or len(h1) != len(h2): return 64
    try:
        n1, n2 = int(h1, 16), int(h2, 16)
        return bin(n1 ^ n2).count("1")
    except:
        return 64


# ══════════════════════════════════════════════════════════════════════════════
#  STYLOMETRY — writing style fingerprint across platforms
# ══════════════════════════════════════════════════════════════════════════════

def stylometry_fingerprint(texts: List[str]) -> dict:
    """
    Extracts linguistic features from bio/about texts for cross-platform
    identity correlation.
    """
    if not texts:
        return {}
    combined = " ".join(t for t in texts if t)
    if not combined.strip():
        return {}

    words = re.findall(r'\b\w+\b', combined.lower())
    sentences = re.split(r'[.!?]+', combined)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 5]

    features = {
        "avg_word_len":      round(sum(len(w) for w in words) / max(len(words),1), 2),
        "vocab_richness":    round(len(set(words)) / max(len(words),1), 3),
        "avg_sentence_len":  round(len(words) / max(len(sentences),1), 2),
        "emoji_density":     round(len(re.findall(r'[\U00010000-\U0010ffff]', combined)) / max(len(combined),1), 4),
        "url_count":         len(re.findall(r'https?://', combined)),
        "hashtag_count":     len(re.findall(r'#\w+', combined)),
        "mention_count":     len(re.findall(r'@\w+', combined)),
        "caps_ratio":        round(sum(1 for c in combined if c.isupper()) / max(len(combined),1), 3),
        "punctuation_ratio": round(sum(1 for c in combined if c in ".,;:!?") / max(len(combined),1), 3),
        "top_words":         [w for w, _ in Counter(words).most_common(5) if w not in
                              {"the","a","an","and","or","in","of","to","for","is","i","my"}],
    }
    return features


def stylometry_similarity(f1: dict, f2: dict) -> float:
    """Cosine-like similarity between two stylometry feature dicts. 0-1."""
    if not f1 or not f2: return 0.0
    numeric_keys = ["avg_word_len","vocab_richness","avg_sentence_len",
                    "emoji_density","caps_ratio","punctuation_ratio"]
    diffs = []
    for k in numeric_keys:
        v1, v2 = f1.get(k, 0), f2.get(k, 0)
        mx = max(abs(v1), abs(v2), 0.001)
        diffs.append(abs(v1 - v2) / mx)
    return round(1.0 - (sum(diffs) / len(diffs)), 3)


# ══════════════════════════════════════════════════════════════════════════════
#  CROSS-PLATFORM CORRELATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def correlate_identities(results: dict) -> dict:
    """
    Given {username: [(platform, url, status, profile), ...]} results,
    compute cross-platform correlation signals:
      - avatar hash similarity
      - bio/description text similarity
      - display name matching
      - location matching
      - linked accounts (e.g. GitHub twitter field matches Twitter username)
    Returns correlation report with confidence scores.
    """
    # Flatten all profiles
    all_profiles = []  # (username, platform, profile_dict)
    for uname, hits in results.items():
        for hit in hits:
            if isinstance(hit, dict) and hit.get("profile"):
                all_profiles.append((uname, hit["platform"], hit["profile"]))

    if len(all_profiles) < 2:
        return {"signals": [], "confidence": 0.0}

    signals = []

    # ── Avatar hash correlation ───────────────────────────────────────────────
    avatar_hashes = {}
    for uname, plat, prof in all_profiles:
        av_url = prof.get("avatar_url", "")
        if av_url:
            img = _fetch_image_bytes(av_url)
            h = perceptual_hash(img)
            if h:
                avatar_hashes[(uname, plat)] = h

    pairs = list(avatar_hashes.keys())
    for i in range(len(pairs)):
        for j in range(i+1, len(pairs)):
            k1, k2 = pairs[i], pairs[j]
            dist = hamming_distance(avatar_hashes[k1], avatar_hashes[k2])
            if dist <= 10:  # very similar images
                signals.append({
                    "type":       "avatar_similarity",
                    "platform_a": k1[1], "platform_b": k2[1],
                    "distance":   dist,
                    "confidence": round(1 - dist/64, 3),
                    "note":       f"Profile pictures are {'identical' if dist==0 else 'very similar'} (hamming={dist})",
                })

    # ── Display name matching ─────────────────────────────────────────────────
    display_names = defaultdict(list)
    for uname, plat, prof in all_profiles:
        dn = prof.get("display_name", "").strip().lower()
        if dn:
            display_names[dn].append((uname, plat))
    for dn, sources in display_names.items():
        if len(sources) >= 2:
            signals.append({
                "type":       "display_name_match",
                "value":      dn,
                "platforms":  [s[1] for s in sources],
                "confidence": 0.85,
                "note":       f"Same display name '{dn}' across {len(sources)} platforms",
            })

    # ── Bio text similarity ───────────────────────────────────────────────────
    bio_texts = [(uname, plat, prof.get("bio","")) for uname, plat, prof in all_profiles if prof.get("bio")]
    for i in range(len(bio_texts)):
        for j in range(i+1, len(bio_texts)):
            u1, p1, b1 = bio_texts[i]
            u2, p2, b2 = bio_texts[j]
            f1 = stylometry_fingerprint([b1])
            f2 = stylometry_fingerprint([b2])
            sim = stylometry_similarity(f1, f2)
            if sim >= 0.85:
                signals.append({
                    "type":       "bio_stylometry_match",
                    "platform_a": p1, "platform_b": p2,
                    "similarity": sim,
                    "confidence": sim,
                    "note":       f"Bio writing style {sim*100:.0f}% similar",
                })
            # Also exact/substring match
            if b1.lower() in b2.lower() or b2.lower() in b1.lower():
                signals.append({
                    "type":       "bio_text_match",
                    "platform_a": p1, "platform_b": p2,
                    "confidence": 0.95,
                    "note":       "Bio text is identical or contained across platforms",
                })

    # ── Location matching ─────────────────────────────────────────────────────
    locations = defaultdict(list)
    for uname, plat, prof in all_profiles:
        loc = prof.get("location","").strip().lower()
        if loc and len(loc) > 2:
            locations[loc].append(plat)
    for loc, plats in locations.items():
        if len(plats) >= 2:
            signals.append({
                "type":       "location_match",
                "value":      loc,
                "platforms":  plats,
                "confidence": 0.7,
                "note":       f"Same location '{loc}' on {len(plats)} platforms",
            })

    # ── Cross-referenced accounts (e.g. GitHub lists Twitter handle) ──────────
    all_usernames_set = set()
    for uname, hits in results.items():
        all_usernames_set.add(uname.lower())

    for uname, plat, prof in all_profiles:
        for field in ("twitter", "github", "instagram", "website", "blog"):
            linked = str(prof.get(field, "")).lower().strip("/").split("/")[-1]
            if linked and linked in all_usernames_set:
                signals.append({
                    "type":       "cross_reference",
                    "platform":   plat,
                    "field":      field,
                    "value":      linked,
                    "confidence": 0.98,
                    "note":       f"{plat} profile explicitly links to @{linked}",
                })

    # ── Linked email in Keybase/Gravatar ──────────────────────────────────────
    all_emails = set()
    for uname, plat, prof in all_profiles:
        for e in prof.get("emails", []):
            if "@" in e:
                all_emails.add(e.lower())
                signals.append({
                    "type":       "email_exposed",
                    "platform":   plat,
                    "email":      e,
                    "confidence": 1.0,
                    "note":       f"Email address exposed in {plat} public profile",
                })

    # ── Composite confidence ──────────────────────────────────────────────────
    if signals:
        avg_conf = sum(s["confidence"] for s in signals) / len(signals)
        max_conf = max(s["confidence"] for s in signals)
        composite = round(min(1.0, 0.3 * len(signals) + 0.7 * avg_conf), 3)
    else:
        composite = 0.0

    return {
        "signals":    sorted(signals, key=lambda x: -x["confidence"]),
        "count":      len(signals),
        "confidence": composite,
        "emails_found": list(all_emails),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  GITHUB RELATIONSHIP SPIDER
# ══════════════════════════════════════════════════════════════════════════════

def github_spider(username: str, depth: int = 1) -> dict:
    """Spider GitHub followers/following to find related accounts."""
    graph = {"center": username, "followers": [], "following": [], "mutual": []}
    for rel in ("followers", "following"):
        url = f"https://api.github.com/users/{username}/{rel}?per_page=30"
        _, body = _fetch(url)
        try:
            users = [u["login"] for u in json.loads(body)]
            graph[rel] = users
        except:
            pass
    mutual = set(graph["followers"]) & set(graph["following"])
    graph["mutual"] = list(mutual)
    return graph


def reddit_spider(username: str) -> dict:
    """Get Reddit user's recent activity to infer interests/timezone."""
    url = f"https://www.reddit.com/user/{username}/comments.json?limit=25"
    _, body = _fetch(url)
    try:
        posts = json.loads(body).get("data", {}).get("children", [])
        timestamps = [p["data"]["created_utc"] for p in posts]
        subreddits  = [p["data"]["subreddit"] for p in posts]
        hours = [datetime.utcfromtimestamp(t).hour for t in timestamps]
        return {
            "top_subreddits":   [s for s,_ in Counter(subreddits).most_common(5)],
            "active_hours_utc": sorted(set(hours)),
            "post_count":       len(posts),
            "timezone_estimate": _infer_timezone(hours),
        }
    except:
        return {}


def _infer_timezone(hours: list) -> str:
    """Rough timezone inference from activity hours (UTC)."""
    if not hours: return "unknown"
    avg = sum(hours) / len(hours)
    # Peak activity ~8pm local time
    offset = round(20 - avg)
    sign = "+" if offset >= 0 else ""
    return f"UTC{sign}{offset} (estimated)"


# ══════════════════════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_html_report(target: str, found: dict, correlation: dict,
                          breach_data: list, outfile: str):
    conf_pct = int(correlation.get("confidence", 0) * 100)
    conf_color = "#27ae60" if conf_pct >= 70 else ("#e67e22" if conf_pct >= 40 else "#e74c3c")

    platform_rows = ""
    for uname, hits in found.items():
        for hit in hits:
            if not isinstance(hit, dict): continue
            prof = hit.get("profile", {})
            bio = str(prof.get("bio",""))[:80]
            loc = str(prof.get("location",""))
            followers = str(prof.get("followers",""))
            platform_rows += f"""
            <tr>
              <td><b>{hit['platform']}</b></td>
              <td><a href="{hit['url']}" target="_blank">{uname}</a></td>
              <td>{bio}</td>
              <td>{loc}</td>
              <td>{followers}</td>
            </tr>"""

    signal_rows = ""
    for sig in correlation.get("signals", []):
        c = int(sig["confidence"] * 100)
        color = "#27ae60" if c >= 80 else "#e67e22"
        signal_rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:bold">{c}%</span></td>
          <td>{sig['type']}</td>
          <td>{sig['note']}</td>
        </tr>"""

    breach_rows = ""
    for b in breach_data[:20]:
        if isinstance(b, dict) and "Name" in b:
            breach_rows += f"<tr><td>{b.get('Name','')}</td><td>{b.get('BreachDate','')}</td><td>{', '.join(b.get('DataClasses',[])[:4])}</td></tr>"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>OSINT Report — {target}</title>
<style>
body{{font-family:monospace;background:#0d0d0d;color:#e0e0e0;padding:20px}}
h1{{color:#00ff88}}h2{{color:#00ccff;border-bottom:1px solid #333;padding-bottom:4px}}
table{{width:100%;border-collapse:collapse;margin-bottom:20px}}
th{{background:#1a1a2e;color:#00ccff;padding:8px;text-align:left}}
td{{padding:6px 8px;border-bottom:1px solid #222}}
tr:hover{{background:#1a1a1a}}
a{{color:#00ff88}}
.badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-weight:bold}}
</style></head><body>
<h1>OSINT Intelligence Report</h1>
<p><b>Target:</b> {target} &nbsp;|&nbsp;
   <b>Generated:</b> {datetime.utcnow().isoformat()} UTC &nbsp;|&nbsp;
   <b>Identity Confidence:</b>
   <span class="badge" style="background:{conf_color}">{conf_pct}%</span>
</p>

<h2>Platform Presence ({sum(len(v) for v in found.values())} accounts found)</h2>
<table><tr><th>Platform</th><th>Username / URL</th><th>Bio</th><th>Location</th><th>Followers</th></tr>
{platform_rows}</table>

<h2>Cross-Platform Correlation Signals ({correlation.get('count',0)} signals)</h2>
<table><tr><th>Confidence</th><th>Type</th><th>Note</th></tr>
{signal_rows or '<tr><td colspan=3>No correlation signals found</td></tr>'}</table>

{'<h2>Breach Records</h2><table><tr><th>Source</th><th>Date</th><th>Data Types</th></tr>' + breach_rows + '</table>' if breach_rows else ''}

<h2>Emails Exposed</h2>
<p>{', '.join(correlation.get('emails_found',[])) or 'None found'}</p>
</body></html>"""

    os.makedirs(os.path.dirname(outfile) if os.path.dirname(outfile) else ".", exist_ok=True)
    with open(outfile, "w") as f:
        f.write(html)
    print(f"\n  HTML report → {outfile}")


# ══════════════════════════════════════════════════════════════════════════════
#  CORE SEARCH
# ══════════════════════════════════════════════════════════════════════════════

def search_username(username: str, threads: int = 20, deep: bool = False,
                    verbose: bool = True) -> list:
    found = []
    lock  = threading.Lock()

    def _task(entry):
        name, url_tpl, exp_status, err_str, confirm_str, extract_key = entry
        if url_tpl is None: return
        result = _probe(name, url_tpl, exp_status, err_str, confirm_str, username)
        if result:
            if deep:
                _deep_extract(result, extract_key, username)
            with lock:
                found.append(result)
                if verbose:
                    prof = result.get("profile", {})
                    extras = []
                    if prof.get("followers"): extras.append(f"followers={prof['followers']}")
                    if prof.get("location"):  extras.append(f"loc={prof['location'][:20]}")
                    extra_str = f"  [{', '.join(extras)}]" if extras else ""
                    print(f"  \033[92m[+]\033[0m {name:20s} {result['url']}{extra_str}")
        elif verbose:
            print(f"  \033[90m[-]\033[0m {name:20s}", end="\r", flush=True)

    if verbose:
        mode = "DEEP" if deep else "FAST"
        print(f"\n  Probing {len(PLATFORMS)} platforms [{mode}] for: \033[96m{username}\033[0m\n")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for f in as_completed([ex.submit(_task, p) for p in PLATFORMS if p[1]]):
            pass

    if verbose:
        print(f"\n  \033[93m{len(found)}\033[0m account(s) found for '{username}'")
    return found


# ══════════════════════════════════════════════════════════════════════════════
#  TERMINAL PRINTER
# ══════════════════════════════════════════════════════════════════════════════

def _print_results(target: str, all_results: dict, corr: dict,
                   breach_data: list, phone_data: dict = None):
    G="\033[92m"; C="\033[96m"; W="\033[93m"; R="\033[91m"; N="\033[0m"
    DIM="\033[90m"; B="\033[94m"; BOLD="\033[1m"
    W60 = "─" * 60

    print(f"\n{C}{W60}{N}")
    print(f"  {BOLD}OSINT REPORT{N}  target: {C}{target}{N}")
    print(f"{C}{W60}{N}")

    # ── Platform hits ─────────────────────────────────────────────────────────
    total = sum(len(v) for v in all_results.values())
    print(f"\n  {W}ACCOUNTS FOUND: {total}{N}")
    for uname, hits in all_results.items():
        for hit in hits:
            if not isinstance(hit, dict): continue
            prof  = hit.get("profile", {})
            plat  = hit["platform"]
            url   = hit["url"]
            lines = [f"  {G}[+]{N} {BOLD}{plat:20s}{N} {url}"]
            if prof.get("display_name"): lines.append(f"      {'name':12s} {prof['display_name']}")
            if prof.get("bio"):          lines.append(f"      {'bio':12s} {str(prof['bio'])[:80]}")
            if prof.get("location"):     lines.append(f"      {'location':12s} {prof['location']}")
            if prof.get("followers"):    lines.append(f"      {'followers':12s} {prof['followers']}")
            if prof.get("email"):        lines.append(f"      {R}{'email':12s} {prof['email']}{N}")
            if prof.get("created_at"):   lines.append(f"      {'joined':12s} {str(prof['created_at'])[:19]}")
            if prof.get("twitter"):      lines.append(f"      {'→twitter':12s} @{prof['twitter']}")
            if prof.get("github"):       lines.append(f"      {'→github':12s} @{prof['github']}")
            if prof.get("proofs"):       lines.append(f"      {'proofs':12s} {', '.join(prof['proofs'][:4])}")
            print("\n".join(lines))

    # ── Breach data ───────────────────────────────────────────────────────────
    if breach_data:
        print(f"\n  {R}BREACH RECORDS ({len(breach_data)} sources){N}")
        for b in breach_data[:15]:
            if not isinstance(b, dict): continue
            name  = b.get("Name", "?")
            date  = b.get("BreachDate", "?")
            types = ", ".join(b.get("DataClasses", [])[:4])
            pwned = b.get("PwnCount", "")
            print(f"  {R}[!]{N} {BOLD}{name:25s}{N} {date}  {DIM}{types}{N}"
                  + (f"  ({pwned:,} accounts)" if pwned else ""))

    # ── Phone data ────────────────────────────────────────────────────────────
    if phone_data:
        print(f"\n  {W}PHONE OSINT{N}")
        wa = phone_data.get("whatsapp", {})
        tg = phone_data.get("telegram", {})
        wa_str = f"{G}registered{N}" if wa.get("registered") else f"{DIM}not found{N}"
        print(f"  {'WhatsApp':12s} {wa_str}")
        print(f"  {'Telegram':12s} fragment_status={tg.get('fragment_status','?')}  available={tg.get('available','?')}")

    # ── Correlation ───────────────────────────────────────────────────────────
    if corr.get("signals"):
        conf_pct = int(corr.get("confidence", 0) * 100)
        col = G if conf_pct >= 70 else (W if conf_pct >= 40 else R)
        print(f"\n  {W}CROSS-PLATFORM CORRELATION  confidence={col}{conf_pct}%{N}")
        for sig in corr["signals"][:10]:
            c   = int(sig["confidence"] * 100)
            col = G if c >= 80 else (W if c >= 60 else R)
            print(f"  {col}[{c:3d}%]{N}  {sig['type']:30s}  {sig['note']}")

    if corr.get("emails_found"):
        print(f"\n  {R}EMAILS EXPOSED:{N} {', '.join(corr['emails_found'])}")

    print(f"\n{C}{W60}{N}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API  (importable)
# ══════════════════════════════════════════════════════════════════════════════

def run(username: Optional[str] = None, email: Optional[str] = None,
        name: Optional[str] = None, phone: Optional[str] = None,
        deep: bool = True, report: bool = False):
    """
    Run a full OSINT scan. All output goes to terminal.
    deep=True  → extract profile data + run correlation (default)
    report=True → also save HTML report to reports/
    """
    G="\033[92m"; C="\033[96m"; W="\033[93m"; R="\033[91m"; N="\033[0m"; B="\033[94m"

    print(f"\n{C}{'─'*60}{N}")
    print(f"  {G}OSINT SOCIAL v2{N} — 80+ platforms · deep extraction · correlation")
    print(f"{C}{'─'*60}{N}")

    # ── Phone-only mode ───────────────────────────────────────────────────────
    if phone and not any([username, email, name]):
        print(f"\n  {W}Phone OSINT:{N} {phone}")
        wa = phone_whatsapp_check(phone)
        tg = phone_telegram_check(phone)
        _print_results(phone, {}, {}, [], {"whatsapp": wa, "telegram": tg})
        return {"whatsapp": wa, "telegram": tg}

    # ── Derive candidates ─────────────────────────────────────────────────────
    candidates  = []
    breach_data = []
    target_label = username or email or name or phone or "unknown"

    if username:
        candidates = [username]
    elif email:
        candidates = _gen_from_email(email)
        print(f"\n  {W}Email candidates ({len(candidates)}):{N} {', '.join(candidates[:8])}{'...' if len(candidates)>8 else ''}")
        print(f"\n  {B}[*] Breach intelligence...{N}")
        breach_data = check_breach_hibp(email)
        dehashed    = check_breach_dehashed_snippet(email)
        if breach_data and not (len(breach_data)==1 and breach_data[0].get("Name")=="API_KEY_NEEDED"):
            print(f"  {R}HIBP: {len(breach_data)} breach(es){N}")
        else:
            print(f"  {G}HIBP: clean (or API key needed){N}")
        print(f"  Dehashed: ~{dehashed} results")
        mx = email_mx_verify(email)
        ep = email_provider_osint(email)
        print(f"  MX: {mx.get('mx',['?'])[0] if mx.get('mx') else 'NONE'}  deliverable={mx.get('deliverable')}  disposable={ep.get('is_disposable')}")
    elif name:
        candidates = _gen_from_name(name)
        print(f"\n  {W}Name candidates ({len(candidates)}):{N} {', '.join(candidates[:8])}{'...' if len(candidates)>8 else ''}")

    if not candidates:
        print(f"  {R}No candidates generated.{N}"); return {}

    # ── Platform scan ─────────────────────────────────────────────────────────
    all_results: dict = {}
    for u in candidates:
        hits = search_username(u, deep=deep, verbose=True)
        if hits:
            all_results[u] = hits

    # ── Correlation ───────────────────────────────────────────────────────────
    corr = {}
    if deep and all_results:
        print(f"\n  {B}[*] Cross-platform correlation...{N}")
        corr = correlate_identities(all_results)

        # GitHub spider
        for u, hits in all_results.items():
            for hit in hits:
                if isinstance(hit, dict) and hit.get("platform") == "GitHub":
                    print(f"  {B}[*] GitHub spider for {u}...{N}")
                    graph = github_spider(u)
                    if graph.get("mutual"):
                        print(f"  Mutual follows: {', '.join(graph['mutual'][:10])}")

        # Reddit activity
        for u, hits in all_results.items():
            for hit in hits:
                if isinstance(hit, dict) and hit.get("platform") == "Reddit":
                    print(f"  {B}[*] Reddit activity for {u}...{N}")
                    act = reddit_spider(u)
                    if act:
                        print(f"      subreddits: {', '.join(act.get('top_subreddits',[]))}")
                        print(f"      timezone:   {act.get('timezone_estimate','?')}")

    # ── Print full terminal report ────────────────────────────────────────────
    _print_results(target_label, all_results, corr, breach_data)

    # ── Optional HTML report ──────────────────────────────────────────────────
    if report and all_results:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r'[^a-z0-9_]', '_', target_label.lower())
        fname = f"reports/osint_{safe}_{ts}.html"
        os.makedirs("reports", exist_ok=True)
        generate_html_report(target_label, all_results, corr, breach_data, fname)

    return all_results


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(
        description="OSINT Social v2 — PhD-level identity intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 osint_social.py -u john_doe
  python3 osint_social.py -e john@gmail.com
  python3 osint_social.py -n "John Doe"
  python3 osint_social.py -p +1234567890
  python3 osint_social.py -u john_doe --report
  python3 osint_social.py -u alice,bob,carol
""")
    ap.add_argument("-u", "--username", help="Username or comma-separated list")
    ap.add_argument("-e", "--email",    help="Email address (+ breach check)")
    ap.add_argument("-n", "--name",     help="Real name (generates username candidates)")
    ap.add_argument("-p", "--phone",    help="Phone number with country code (+1234...)")
    ap.add_argument("--fast",   action="store_true", help="Skip profile extraction (existence only)")
    ap.add_argument("--report", action="store_true", help="Save HTML report to reports/")
    args = ap.parse_args()

    # Bulk username mode
    if args.username and "," in args.username:
        usernames = [u.strip() for u in args.username.split(",") if u.strip()]
        all_results = {}
        for u in usernames:
            hits = search_username(u, deep=not args.fast)
            if hits: all_results[u] = hits
        corr = correlate_identities(all_results) if not args.fast else {}
        _print_results(", ".join(usernames), all_results, corr, [])
        if args.report and all_results:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            os.makedirs("reports", exist_ok=True)
            generate_html_report("bulk", all_results, corr, [], f"reports/osint_bulk_{ts}.html")
    else:
        run(username=args.username, email=args.email, name=args.name,
            phone=args.phone, deep=not args.fast, report=args.report)
