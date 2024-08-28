# Debian ELTS Advisories

Security Advisories for Debian Extended LTS, re-published in the OSV format.
Automatically updated. [Source][source] is the Freexian Security Tracker
repository.

## Background

- Debian LTS is maintained by the Debian Security team
- Debian Extended LTS (ELTS), is a commercial offering is maintained by Freexian.
- Debian ELTS Advisories are announced at <https://www.freexian.com/lts/extended/updates/>
- [OSV](https://ossf.github.io/osv-schema/) is a Open Source Vulnerability format, as specified by the [Open Source Security Foundation](https://openssf.org).

## Contributing

Contributions are welcome! Since the advisories are automatically generated, please don't make
manual updates to the JSON advisory files. Instead update the generation script: `main.py`.

## Source:

- Updates are fetched from the [ELTS Security Tracker][source].
- The data is also published at <https://deb.freexian.com/extended-lts/tracker/data/json>,
  but it doesn't include the announcement URLs, and is harder to use.
- See https://github.com/ossf/osv-schema/pull/104 for more information.

## License

The code is licensed under MIT. The license information for security advisories is unclear.

[source]: https://salsa.debian.org/freexian-team/extended-lts/security-tracker/-/blob/master/data/ELA/list
