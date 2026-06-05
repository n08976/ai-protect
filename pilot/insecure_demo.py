"""ai-protect GitHub Actions pilot fixture.

A deliberately-insecure call so the assure.yml gate fails on a HIGH finding,
gets auto-fixed (verify=False -> verify=True) and verified by a re-scan, and
re-gates green — with a fix PR opened. Safe to delete after the demo.
"""
import requests


def fetch(url):
    # bandit B501 / semgrep: TLS verification disabled (HIGH)
    return requests.get(url, verify=True)
