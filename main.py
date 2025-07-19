import urllib.request
import json
import re
import datetime
from time import sleep

TITLE_REGEX = r"\[(?P<date>\d+ \w+ \d{4})\] (?P<id>ELA-\d+-\d+) (?P<package>[\w\-\.]+) - (?P<type>[\w ]+)"
CVE_REGEX = r"CVE-\d{4}-\d{4,7}"
DETAILS_REGEX = r"\[(?P<codename>\w+)\] - (?P<package>[\w\-\.]+) (?P<version>(?:(?:[0-9]{1,9}):)?(?:[0-9][0-9a-z\.+~-]*)(?:(?:-[0-0a-z\.+~]+))?)"
ELA_LIST_URL = "https://salsa.debian.org/freexian-team/extended-lts/security-tracker/-/raw/master/data/ELA/list"
RFC3339_FORMATSTRING = "%Y-%m-%dT%H:%M:%SZ"
DEBIAN_CODENAME = {
    "bookworm": "12",
    "bullseye": "11",
    "buster": "10",
    "stretch": "9",
    "jessie": "8",
    "wheezy": "7",
    "squeeze": "6",
}


def fetch_ela_list(retry = 5):
    for attempt in range(retry):
        try:
            response = urllib.request.urlopen(ELA_LIST_URL)
            return response.read().decode("utf-8")
        except urllib.error.URLError as e:
            if attempt < retry - 1:
                print(f"Attempt {attempt + 1} failed, retrying...")
                sleep(10)
            else:
                raise e


def parse_date(s):
    # '15 Jun 2018'
    return datetime.datetime.strptime(s, "%d %b %Y")

def format_as_rfc3339(timestamp):
    return timestamp.strftime(RFC3339_FORMATSTRING)

def get_osv():
    content = fetch_ela_list()
    cves = None
    details = []
    data = None
    for line in content.split("\n"):
        line = line.strip()
        m = re.match(TITLE_REGEX, line)
        if m:
            if cves and data and len(details) > 0:
                yield {
                    "id": data["id"],
                    "modified": format_as_rfc3339(parse_date(data["date"])),
                    "related": cves,
                    "affected": [
                        {
                            "package": {
                                "ecosystem": f"Debian:{DEBIAN_CODENAME[r['codename']]}",
                                "name": r["package"],
                                "purl": f"pkg:deb/debian/{data['package']}?distro={r['codename']}&repository_url=http%3A%2F%2Fdeb.freexian.com%2Fextended-lts",
                            },
                            "ranges": [{
                                "type": "ECOSYSTEM",
                                "events": [
                                    {
                                        "introduced": "0"
                                    },
                                    {
                                        "fixed": r["version"],
                                    }
                                ],
                            }],
                        }
                        for r in details
                    ],
                    "database_specific": {"type": data["type"]},
                    "references": [
                        {
                            "type": "ADVISORY",
                            "url": f"https://deb.freexian.com/extended-lts/tracker/{data['id']}",
                        }
                    ]
                    + [
                        {
                            "type": "ADVISORY",
                            "url": f"https://deb.freexian.com/extended-lts/tracker/{cve}",
                        }
                        for cve in cves
                    ],
                }
                details = []
                cves = None
            data = m.groupdict()
        m = re.findall(CVE_REGEX, line)
        if len(m) > 0:
            cves = re.findall(CVE_REGEX, line)
        m = re.search(DETAILS_REGEX, line)
        if m:
            details.append(m.groupdict())


def __main__():
    for d in get_osv():
        fn = f"advisories/{d['id']}.json"
        with open(fn, "w") as f:
            print(f"writing to {fn}")
            f.write(json.dumps(d, indent=4, sort_keys=True))


if __name__ == "__main__":
    __main__()
