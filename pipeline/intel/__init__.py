"""External intel feeds — CVE/threat feeds fetched and surfaced in the UI.

Feeds are configured in `~/.ai-protect/feeds.jsonl`, items land in
`~/.ai-protect/intel.jsonl`, and fetch attempts are logged to
`~/.ai-protect/feed_fetches.jsonl`. Adapters may consult IntelStore later;
for now, intel is read-only context next to findings.
"""
