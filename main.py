import urllib.request
import os
import json
import xml.dom.minidom
import re
from bs4 import BeautifulSoup


def fetch_advisory(url, ela_id):
    debian_regex = (
        r"(?P<v>(?:(?:[0-9]{1,9}):)?(?:[0-9][0-9a-z\.+~-]*)(?:(?:-[0-0a-z\.+~]+))?)"
    )
    response = urllib.request.urlopen(url)
    html = response.read()
    soup = BeautifulSoup(html, "html.parser").find("main")
    d = list(soup.find_all("td"))
    cves = []
    date = None
    if len(d) < 3:
        print(f"Skipping {url}, not enough data")
        return None
    cves = [x.strip() for x in d[2].text.strip().split("\n")]
    if len(d) >= 1:
        packages = [d[0].text]
    if len(d) >= 2:
        versions = re.findall(debian_regex, d[1].text)
    if soup.find("span"):
        date = soup.find("span").text
    vuln_type = None
    if soup.find("p"):
        vuln_type = soup.find("p").text.strip()

    return {
        "id": ela_id,
        "refs": [f"https://deb.freexian.com/extended-lts/tracker/{ela_id}", url],
        "title": soup.find("h1").text,
        "type": vuln_type,
        "date": date,
        "packages": packages,
        "versions": versions,
        "cves": cves,
    }

if __name__ == "__main__":
    sitemap_url = "https://www.freexian.com/en/sitemap.xml"
    contents = urllib.request.urlopen(sitemap_url)
    d = xml.dom.minidom.parse(contents)
    for x in d.getElementsByTagName("loc"):
        url = x.childNodes[0].nodeValue
        if url.startswith("https://www.freexian.com/lts/extended/updates/ela-"):
            slug = url.split("/")[-2]
            ela_id = re.match(r"^(ela-\d+\-\d+)", slug)[0].upper()
            fn = f"advisories/{ela_id}.json"

            if not os.path.exists(fn):
                data = fetch_advisory(url, ela_id)
                if not data:
                    print(f"Failed to fetch {ela_id}")
                    continue
                with open(fn, "w") as f:
                    print(f"writing to {fn}")
                    f.write(json.dumps(data, indent=4, sort_keys=True))
