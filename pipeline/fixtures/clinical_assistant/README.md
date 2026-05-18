# clinical_assistant fixture

Empty source root for the `example_clinical_assistant` manifest. Holds whatever
small synthetic source the fixture manifest scans — currently empty, so SAST
adapters report nothing and SCA adapters report no installed deps.

If you want the fixture to surface findings for demonstration, drop a small
Python file here with a known anti-pattern (e.g. `eval(user_input)`) and a
`requirements.txt` with a pinned vulnerable package version.
