#!/usr/bin/env python3
from __future__ import annotations
import argparse, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; CHANGELOG=ROOT/'CHANGELOG.md'
def normalize_version(value:str)->str:
    value=value.strip(); value=value[1:] if value.lower().startswith('v') else value
    if not value: raise ValueError('Version cannot be empty.')
    return value
def extract_version_section(text:str, version:str)->str:
    version=normalize_version(version)
    m=re.search(rf'^##\s+{re.escape(version)}(?:\s+.*)?$', text, re.MULTILINE)
    if m is None: raise ValueError(f'CHANGELOG.md does not contain a section for version {version}.')
    start=m.end(); nxt=re.search(r'^##\s+', text[start:], re.MULTILINE); end=start+nxt.start() if nxt else len(text)
    body=text[start:end].strip()
    if not body: raise ValueError(f'Changelog section {version} is empty.')
    return f'{text[m.start():m.end()].strip()}\n\n{body}\n'
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('version'); ap.add_argument('--output', type=Path); a=ap.parse_args()
    try: notes=extract_version_section(CHANGELOG.read_text(), a.version)
    except (OSError,ValueError) as e: print(f'error: {e}',file=sys.stderr); return 1
    if a.output:a.output.write_text(notes)
    else:sys.stdout.write(notes)
    return 0
if __name__=='__main__': raise SystemExit(main())
