#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Owner-run management of the home gateway's Supgang UDP forward.

Supports the AT&T BGW320 family web interface (HUMAX/ARRIS, ``/cgi-bin/*.ha``).
The owner runs this and types the device access code at a hidden prompt; the
code is never read from arguments, the environment or a file, and is never
printed or stored. Supgang itself never edits a router: this is a separate tool.

    tools/gateway.py                 # read-only: log in, show the plan, save the pages
    tools/gateway.py --apply         # show the plan, then submit it after typing "yes"
    tools/gateway.py --inventory     # read-only: every setting page, current values and options

Without --apply nothing is submitted except the login. Gateway pages are saved
to a private directory so a mismatch can be diagnosed without guessing.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import http.cookiejar
import os
import re
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

GATEWAY = "http://192.168.1.254"
LOGIN = "/cgi-bin/login.ha"
NAT_GAMING = "/cgi-bin/apphosting.ha"
TIMEOUT = 10
SITE_MAP = "/cgi-bin/sitemap.ha"
# Pages whose markup carries secrets (Wi-Fi keys, the access code, voice
# credentials) are neither saved nor summarised; actions are never fetched.
SKIPPED_PAGES = {"wconfig_unified", "wmacauth", "routerpasswd", "voiceconfig", "reset", "restart", "update"}
SECRET_FIELD = re.compile(r"passw|passphrase|psk|key|secret|accesscode|(^|_)pin($|_)", re.I)
MAX_PAGE = 512 * 1024


@dataclass
class Form:
    action: str
    method: str
    fields: dict[str, str] = field(default_factory=dict)
    texts: list[str] = field(default_factory=list)
    radios: dict[str, list[str]] = field(default_factory=dict)
    selects: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    submits: list[tuple[str, str]] = field(default_factory=list)


class Forms(HTMLParser):
    """Collects every form with its fields, options and submit buttons."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self.links: list[tuple[str, str]] = []
        self._select: str | None = None
        self._option: str | None = None
        self._link: str | None = None
        self._text = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {key: value or "" for key, value in attrs}
        if tag == "form":
            self.forms.append(Form(a.get("action", ""), a.get("method", "get").lower()))
        elif tag == "a" and a.get("href"):
            self._link, self._text = a["href"], ""
        elif not self.forms:
            return
        form = self.forms[-1] if self.forms else None
        if form is None:
            return
        kind = a.get("type", "text").lower()
        name = a.get("name", "")
        if tag == "input" and name:
            if kind == "submit":
                form.submits.append((name, a.get("value", "")))
            elif kind == "radio":
                form.radios.setdefault(name, []).append(a.get("value", ""))
                if "checked" in a:
                    form.fields[name] = a.get("value", "")
            elif kind == "checkbox":
                if "checked" in a:
                    form.fields[name] = a.get("value", "on")
            else:
                form.fields[name] = a.get("value", "")
                if kind == "text":
                    form.texts.append(name)
        elif tag == "select" and name:
            self._select = name
            form.selects[name] = []
        elif tag == "option" and self._select:
            self._option, self._text = a.get("value", ""), ""
            if "selected" in a:
                form.fields[self._select] = a.get("value", "")
        elif tag == "button" and name:
            form.submits.append((name, a.get("value", "")))

    def handle_data(self, data: str) -> None:
        self._text += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "option" and self._select is not None and self._option is not None and self.forms:
            self.forms[-1].selects[self._select].append((self._option, " ".join(self._text.split())))
            self._option = None
        elif tag == "select":
            self._select = None
        elif tag == "a" and self._link is not None:
            self.links.append((self._link, " ".join(self._text.split())))
            self._link = None


class Gateway:
    def __init__(self, base: str, capture: Path) -> None:
        self.base = base
        self.capture = capture
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.pages = 0

    def fetch(self, path: str, data: dict[str, str] | None = None) -> str:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        request = urllib.request.Request(urllib.parse.urljoin(self.base, path), data=body)
        with self.opener.open(request, timeout=TIMEOUT) as response:
            text = response.read(MAX_PAGE + 1).decode("utf-8", "replace")
        if len(text) > MAX_PAGE:
            raise SystemExit("gateway page exceeded the size bound")
        self.pages += 1
        name = re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-") or "root"
        (self.capture / f"{self.pages:02d}-{name}{'-post' if data is not None else ''}.html").write_text(text)
        return text

    def login(self, code: str) -> None:
        self.fetch(LOGIN)
        page = self.fetch(LOGIN)
        form = next((f for f in parse(page).forms if "nonce" in f.fields and "hashpassword" in f.fields), None)
        if form is None:
            raise SystemExit("the gateway's login form was not found; see the saved pages")
        nonce = form.fields["nonce"]
        result = self.fetch(
            form.action or LOGIN,
            {
                "nonce": nonce,
                "password": "*" * len(code),
                "hashpassword": hashlib.md5((code + nonce).encode()).hexdigest(),
                "Continue": "Continue",
            },
        )
        if any("hashpassword" in f.fields for f in parse(result).forms):
            raise SystemExit("the gateway refused the access code (or a login lockout is active)")


def parse(page: str) -> Forms:
    forms = Forms()
    forms.feed(page)
    return forms


def text_of(page: str) -> str:
    """Visible page text, without menus: a name offered in a drop-down is not
    evidence that it is configured."""
    stripped = re.sub(r"<script.*?</script>|<style.*?</style>|<select.*?</select>", " ", page, flags=re.S | re.I)
    return " ".join(re.sub(r"<[^>]+>", " ", stripped).split())


def only(candidates: list[str], what: str) -> str:
    if len(candidates) != 1:
        raise LookupError(f"{what}: expected exactly one match, found {candidates or 'none'}")
    return candidates[0]


def custom_service_plan(form: Form, name: str, port: int) -> dict[str, str]:
    """Maps the Custom Services form's fields by their names, refusing ambiguity."""
    texts = [n for n in form.texts if n != "nonce"]
    lowered = {n: n.lower() for n in texts}
    service = only([n for n, l in lowered.items() if "name" in l or "service" in l], "service-name field")
    ports = [n for n in texts if n != service]
    base = only([n for n in ports if re.search(r"base|host", lowered[n])], "base host port field")
    ranges = [n for n in ports if n != base]
    if len(ranges) != 2:
        raise LookupError(f"port range fields: expected two, found {ranges}")
    plan = dict(form.fields)
    plan.update({service: name, ranges[0]: str(port), ranges[1]: str(port), base: str(port)})
    protocol = [(n, v) for n, values in form.radios.items() for v in values if v.lower() == "udp"]
    protocol += [
        (n, v) for n, options in form.selects.items() for v, label in options if label.lower() == "udp" or v.lower() == "udp"
    ]
    key, value = only([f"{n}={v}" for n, v in protocol], "UDP protocol choice").split("=", 1)
    plan[key] = value
    add = only([f"{n}={v}" for n, v in form.submits if v.lower() == "add"], "Add button")
    key, value = add.split("=", 1)
    plan[key] = value
    return plan


def hosting_plan(form: Form, service: str, device: str) -> dict[str, str]:
    """Selects the service and the device in the NAT/Gaming hosting form."""
    def choose(label: str, what: str) -> tuple[str, str]:
        matches = [
            f"{n}={v}" for n, options in form.selects.items() for v, text in options if label.lower() in text.lower()
        ]
        return tuple(only(matches, what).split("=", 1))  # type: ignore[return-value]

    plan = dict(form.fields)
    for key, value in (choose(service, f"service option '{service}'"), choose(device, f"device option '{device}'")):
        plan[key] = value
    key, value = only([f"{n}={v}" for n, v in form.submits if v.lower() == "add"], "Add button").split("=", 1)
    plan[key] = value
    return plan


def show(title: str, action: str, plan: dict[str, str]) -> None:
    print(f"\n{title}\n  POST {action}")
    for key, value in plan.items():
        print(f"    {key} = {'<nonce>' if key == 'nonce' else value}")


def confirm() -> bool:
    try:
        return input('\nType "yes" to submit this to the gateway: ').strip() == "yes"
    except EOFError:
        return False


def inventory(gateway: Gateway) -> int:
    """Fetches every listed settings page (GET only) and prints each form's
    current values and choices, so the available controls can be reviewed."""
    pages = sorted(set(re.findall(r'href="(/cgi-bin/[a-z0-9_]+\.ha)"', gateway.fetch(SITE_MAP))))
    for path in pages:
        stem = path.rsplit("/", 1)[-1].removesuffix(".ha")
        if stem in SKIPPED_PAGES or stem in {"login", "sitemap"}:
            continue
        try:
            page = gateway.fetch(path)
        except OSError as error:
            print(f"\n== {path}: {type(error).__name__}")
            continue
        title = re.search(r"<title>(.*?)</title>", page, re.S | re.I)
        print(f"\n== {path} ({title.group(1).strip() if title else ''})")
        for form in parse(page).forms:
            for name, value in form.fields.items():
                if name == "nonce":
                    continue
                shown = "<hidden>" if SECRET_FIELD.search(name) else value
                options = form.selects.get(name) or [(v, v) for v in form.radios.get(name, [])]
                choices = f"  choices: {', '.join(label or v for v, label in options)[:160]}" if options else ""
                print(f"   {name} = {shown}{choices}")
            for name, values in form.radios.items():
                if name not in form.fields:
                    print(f"   {name} = (none)  choices: {', '.join(values)[:160]}")
            if form.submits:
                print(f"   buttons: {', '.join(v for _, v in form.submits)[:160]}")
    print(f"\nRead-only inventory: nothing was submitted. Pages are saved in {gateway.capture}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="submit the plan after an explicit confirmation")
    mode.add_argument("--inventory", action="store_true", help="read every settings page; submit nothing")
    parser.add_argument("--service", default="Supgang")
    parser.add_argument("--port", type=int, default=44330)
    parser.add_argument("--device", default="MacSolis", help="device name as the gateway lists it")
    parser.add_argument("--gateway", default=GATEWAY)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1 through 65535")
    if not sys.stdin.isatty():
        raise SystemExit("run this in a terminal: the access code is read only from a hidden prompt")

    capture = Path(tempfile.mkdtemp(prefix="supgang-gateway-"))
    os.chmod(capture, 0o700)
    gateway = Gateway(args.gateway, capture)
    gateway.login(getpass.getpass("Gateway device access code (hidden): "))
    print(f"Logged in. Pages are saved privately in {capture}")
    if args.inventory:
        return inventory(gateway)

    nat = gateway.fetch(NAT_GAMING)
    if re.search(rf"\b{re.escape(args.service)}\b.*?\b{re.escape(args.device)}\b", text_of(nat), re.I | re.S):
        print(f"\nAlready configured: {args.service} is hosted on {args.device}. Nothing to change.")
        return 0

    nat_forms = parse(nat)
    services_link = next(
        (href for href, label in nat_forms.links if "custom" in label.lower() or "services" in href.lower()), None
    )
    services_form = next((f for f in nat_forms.forms for _, v in f.submits if "custom" in v.lower()), None)
    if services_link:
        services_page = gateway.fetch(services_link)
    elif services_form:
        button = next(f"{n}={v}" for n, v in services_form.submits if "custom" in v.lower())
        key, value = button.split("=", 1)
        services_page = gateway.fetch(services_form.action or NAT_GAMING, {**services_form.fields, key: value})
    else:
        print("\nCould not find the Custom Services page from NAT/Gaming. Share this folder for a precise fix:")
        print(f"  {capture}")
        return 2

    service_exists = re.search(rf"\b{re.escape(args.service)}\b", text_of(services_page), re.I) is not None
    try:
        if not service_exists:
            services = parse(services_page)
            form = next(f for f in services.forms if len(f.texts) >= 3)
            add_service = custom_service_plan(form, args.service, args.port)
            show(f"Step 1: create custom service {args.service} (UDP {args.port})", form.action, add_service)
        hosting_form = next(f for f in nat_forms.forms if f.selects)
    except (LookupError, StopIteration) as error:
        print(f"\nThe gateway's forms did not match unambiguously ({error}). Nothing was submitted.")
        print(f"Share this folder so the exact fields can be pinned: {capture}")
        return 2
    print(f"\nStep 2: host {args.service} on {args.device} (the device's options are read after step 1)")

    if not args.apply:
        print("\nRead-only run: nothing was changed. Re-run with --apply to submit.")
        return 0
    if not confirm():
        print("Not confirmed. Nothing was submitted.")
        return 1

    if not service_exists:
        gateway.fetch(form.action or services_link or NAT_GAMING, add_service)
        time.sleep(1)
    nat = gateway.fetch(NAT_GAMING)
    try:
        hosting_form = next(f for f in parse(nat).forms if f.selects)
        host = hosting_plan(hosting_form, args.service, args.device)
    except (LookupError, StopIteration) as error:
        print(f"\nThe service exists but hosting could not be matched ({error}). Share {capture}")
        return 2
    show(f"Step 2: host {args.service} on {args.device}", hosting_form.action, host)
    if not confirm():
        print("Not confirmed. The custom service exists but is not hosted on any device.")
        return 1
    gateway.fetch(hosting_form.action or NAT_GAMING, host)
    final = text_of(gateway.fetch(NAT_GAMING))
    if re.search(rf"\b{re.escape(args.service)}\b.*?\b{re.escape(args.device)}\b", final, re.I | re.S):
        print(f"\nDone: {args.service} (UDP {args.port}) is hosted on {args.device}.")
        return 0
    print(f"\nSubmitted, but the NAT/Gaming page does not show the hosted application. Share {capture}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
