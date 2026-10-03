# Sources and attribution

The generator implementation in this repository is licensed under MIT.
That license does not relicense third-party datasets.

- Architecture and reviewed OpenAI domain snapshots:
  [poohyeban/shadowrocket-rules](https://github.com/poohyeban/shadowrocket-rules),
  reference commit `5fba80b796554b51fa934b0ed71c19d97a36974b`.
  The converter implementation here is independent; no Git history, local
  configuration or generated Shadowrocket lists are imported.
- Domain classifications:
  [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)
  ([MIT license](https://github.com/v2fly/domain-list-community/blob/master/LICENSE)).
- Country and ASN data: GeoLite2 data created by
  [MaxMind](https://www.maxmind.com), distributed through
  [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb).
  [GeoLite2 data and attribution](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).
- AdGuard derived hostname subset:
  [AdguardTeam/AdGuardSDNSFilter](https://github.com/AdguardTeam/AdGuardSDNSFilter)
  ([upstream license](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE)).
  Upstream combines multiple public filters; provenance and their notices remain
  available in the original filter headers and linked source repository.
  The derived `rules/AdGuard/` dataset is distributed under GPL-3.0;
  see `LICENSES/AdGuard-GPL-3.0.txt`. Its modifications are the Loon conversion,
  hostname-only selection, exception subtraction and compaction described in
  the README. Initial conversion: 2026-10-03. The generator and conversion
  report supply the transformation details. The independent generator code
  remains MIT-licensed.
- ChatGPT Voice network prefixes:
  [OpenAI JSON](https://openai.com/chatgpt-voice.json).
- Reviewed domain facts:
  [OpenAI network recommendations](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps).
  The full reviewed list and routing exclusions are maintained separately.

Input hashes are recorded in `reports/manifest.json`; exclusions, approximations
that only reduce blocking, and skipped patterns are recorded in the conversion
report. Rules are derived classifications, not statements of domain ownership.
The v2fly attribution and full license are retained in `LICENSES/v2fly-MIT.txt`.
