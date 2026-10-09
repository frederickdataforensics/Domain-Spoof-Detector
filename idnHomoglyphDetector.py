# -*- coding: utf-8 -*-
"""
Created on Fri Sep  4 14:27:20 2026

@author: ICompyle
Educational IDN/Homoglyph hostname detector.
The program analyzes text only. It never connects to or visits the supplied url.
"""

#!/usr/bin/env python3

from __future__ import annotations
from urllib.parse import urlsplit 
from pathlib import Path
import argparse
import ipaddress
from domain_structure import misleading_subdomain
import json
import unicodedata
from dataclasses import asdict, dataclass


# A deliberately small, explainable map of common Greek/Cyrillic look-alikes
# It is not a complete implementation of Unicode confusable detection
CONFUSABLES = {
    # Cyrillic
    "а": "a", "А": "a", "е": "e", "Е": "e", "о": "o", "О": "o",
    "р": "p", "Р": "p", "с": "c", "С": "c", "х": "x", "Х": "x",
    "у": "y", "У": "y", "і": "i", "І": "i", "ј": "j", "Ј": "j",
    "к": "k", "К": "k", "м": "m", "М": "m", "т": "t", "Т": "t",
    "в": "b", "В": "b", "н": "h", "Н": "h", "ӏ": "l", "Ӏ": "l",
    # Greek
    "Α": "a", "α": "a", "Β": "b", "Ε": "e", "ε": "e", "Ζ": "z",
    "Η": "h", "Ι": "i", "ι": "i", "Κ": "k", "κ": "k", "Μ": "m",
    "Ν": "n", "Ο": "o", "ο": "o", "Ρ": "p", "ρ": "p", "Τ": "t",
    "Υ": "y", "Χ": "x", "χ": "x",
}

# ASCII characters and character sequences commonly chosen for visual similarity
# These are only treated as meaningful when compared with a user-supplied trusted
# domain, because digits and repeated letters are legitimate in many domains.
ASCII_LOOKALIKES = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",        
}


def codepoints_to_text(codepoints: str) -> str:
    """Convert hexadecimal Unicode code points into text."""
    return "".join(
        chr(int(code_point, 16))
        for code_point in codepoints.split()
    )


def load_confusables(file_path: Path) -> tuple[dict[str, str], str]:
    """Load Unicode confusable mappings and dataset version."""
    mappings = {}
    version = "unknown"

    with file_path.open("r", encoding="utf-8") as confusables_file:
        for line in confusables_file:
            if line.startswith("# Version:"):
                version = line.split(":", maxsplit=1)[1].strip()

            data = line.split("#", maxsplit=1)[0].strip()

            if not data:
                continue

            fields = [
                field.strip()
                for field in data.split(";")
            ]

            if len(fields) < 2:
                continue

            source = codepoints_to_text(fields[0])
            target = codepoints_to_text(fields[1])

            mappings[source] = target

    return mappings, version


PROGRAM_DIRECTORY = Path(__file__).resolve().parent
CONFUSABLES_FILE = PROGRAM_DIRECTORY / "confusables.txt"

if CONFUSABLES_FILE.exists():
    UNICODE_CONFUSABLES, CONFUSABLES_VERSION = load_confusables(
        CONFUSABLES_FILE
    )
else:
    # Keep the program usable when the Unicode dataset has not yet been
    # installed, while making the reduced coverage explicit to callers.
    UNICODE_CONFUSABLES = CONFUSABLES.copy()
    CONFUSABLES_VERSION = "built-in fallback map"



ASCII_SEQUENCE_LOOKALIKES = {
    "rn": "m", "vv": "w", "cl": "d"    
}

@dataclass
class Finding:
    severity: str
    reason: str
    detail: str
    
@dataclass 
class CharacterDetail:
    index: int
    character: str
    code_point: str
    unicode_name: str
    script: str 
    looks_like: str | None
    
@dataclass 
class Report:
    input_value: str
    hostname: str
    unicode_hostname: str 
    ascii_hostname: str
    scripts: list[str]
    skeleton: str
    character_details: list[CharacterDetail]
    risk_score: int 
    verdict: str
    findings: list[Finding] 
    

def extract_hostname(value: str) -> str:
    """Extract a hostname without making network request"""
    candidate = value.strip()
    if not candidate:
        raise ValueError("Input is empty")
        
        
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    if not parsed.hostname:
        raise ValueError("Could not extract hostname")
    return parsed.hostname.rstrip(".").lower()


def defang_hostname(hostname: str) -> str:
    """Return a non-clickable display form of an extracted hostname."""
    return hostname.replace(".", "[.]")


def sanitized_defanged_display(value: str) -> str:
    """
    Parse untrusted input without connecting to it and return only a
    sanitized, defanged hostname for display.

    Paths, query strings, fragments, and embedded credentials are not
    included in the returned value.
    """
    hostname = extract_hostname(value)
    return defang_hostname(hostname)


def unicode_hostname(hostname: str) -> str:
    labels = []
    for label in hostname.split("."):
        try:
            labels.append(label.encode("ascii").decode("idna"))
        except UnicodeError:
            labels.append(label)
    return ".".join(labels).lower()


def ascii_hostname(hostname: str) -> str:
    labels = []
    for label in hostname.split("."):
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            labels.append("<invalid-idn>")
    return ".".join(labels).lower()


def character_script(char: str) -> str | None:
    if char.isascii():
        return "Latin" if char.isalpha() else None

    name = unicodedata.name(char, "")

    for script in (
        "LATIN",
        "CYRILLIC",
        "GREEK",
        "HEBREW",
        "ARABIC",
        "ARMENIAN",
    ):
        if script in name:
            return script.title()

    return "Other" if char.isalpha() else None



def scripts_in(hostname: str) -> list[str]:
    return sorted({script for char in hostname if (script := character_script(char))})


def mixed_script_labels(hostname: str) -> list[tuple[str, list[str]]]:
    mixed_labels = []

    for label in hostname.split("."):
        label_scripts = scripts_in(label)

        if len(label_scripts) > 1:
            mixed_labels.append((label, label_scripts))

    return mixed_labels



def make_skeleton(hostname: str) -> str:
    """Create a visual skeleton using Unicode confusable mappings."""
    normalized = unicodedata.normalize(
        "NFD",
        hostname.casefold()
    )

    output = []

    for character in normalized:
        replacement = UNICODE_CONFUSABLES.get(
            character,
            character
        )
        output.append(replacement)

    skeleton = "".join(output)

    return unicodedata.normalize("NFD", skeleton)


def make_ascii_skeleton(hostname: str) -> str:
    skeleton = "".join(ASCII_LOOKALIKES.get(char, char) for char in hostname.casefold())
    for lookalike, replacement in ASCII_SEQUENCE_LOOKALIKES.items():
        skeleton = skeleton.replace(lookalike, replacement)
    return skeleton


def edit_distance(left: str, right: str) -> int:
    """Calculate Levenshtein distance: insertions, deletions, or substitutions."""
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            current.append(min(
                current[-1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + (left_char != right_char),
            ))
        previous = current
    return previous[-1]


def is_adjacent_transposition(left: str, right: str) -> bool:
    if len(left) != len(right):
        return False
    differences = [i for i, pair in enumerate(zip(left, right)) if pair[0] != pair[1]]
    return (
        len(differences) == 2
        and differences[1] == differences[0] + 1
        and left[differences[0]] == right[differences[1]]
        and left[differences[1]] == right[differences[0]]
    )


def inspect_characters(hostname: str) -> list[CharacterDetail]:
    """Return forensic-style metadata for non-ASCII/confusable characters."""
    details = []
    for index, char in enumerate(hostname):
        if ord(char) <= 127 and char not in ASCII_LOOKALIKES:
            continue
        details.append(CharacterDetail(
            index=index,
            character=char,
            code_point=f"U+{ord(char):04X}",
            unicode_name=unicodedata.name(char, "UNASSIGNED/UNKNOWN"),
            script=character_script(char) or "Common",
            looks_like=(
            UNICODE_CONFUSABLES.get(char)
            or ASCII_LOOKALIKES.get(char)
),
        ))
    return details


def normalize_trusted_domain(value: str) -> str:
    return unicode_hostname(extract_hostname(value))


def analyze(value: str, trusted_domains: list[str] | None = None) -> Report:
    hostname = extract_hostname(value)
    decoded = unicode_hostname(hostname)
    encoded = ascii_hostname(decoded)
    scripts = scripts_in(decoded)
    mixed_labels = mixed_script_labels(decoded)
    skeleton = make_skeleton(decoded)
    character_details = inspect_characters(decoded)
    findings: list[Finding] = []
    score = 0


    if any(
        label.startswith("xn--")
        for label in hostname.split(".")
    ):
        findings.append(Finding(
            "info",
            "Punycode label",
            f"The displayed ASCII form is {encoded}."
        ))
        score += 10

    if mixed_labels:
        details = "; ".join(
            f"{label!r}: {', '.join(label_scripts)}"
            for label, label_scripts in mixed_labels
        )

        findings.append(Finding(
            "high",
            "Mixed writing systems within a label",
            details
        ))
        score += 35

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return Report(value, hostname, decoded, encoded, [], skeleton, [], 0,
                      "No IDN risk indicators", [])
    except ValueError:
        pass

    if any(ord(char) > 127 for char in decoded):
        findings.append(Finding("medium", "Unicode hostname",
                                "The hostname contains non-ASCII characters."))
        score += 25

    mapped = [
        (char, UNICODE_CONFUSABLES[char])
        for char in decoded
        if not char.isascii() and char in UNICODE_CONFUSABLES
    ]
    if mapped:
        examples = ", ".join(f"{char!r}->{replacement!r}" for char, replacement in mapped[:8])
        findings.append(Finding("high", "ASCII-like homoglyphs", examples))
        score += min(30, 10 + len(mapped) * 5)

    for trusted in trusted_domains or []:
        trusted_unicode = normalize_trusted_domain(trusted)
        misleading_domain = misleading_subdomain(
            encoded, ascii_hostname(trusted_unicode)
        )
        if misleading_domain:
            findings.append(Finding(
                "critical", "Misleading trusted name in subdomain",
                f"The expected name appears before the actual site domain {misleading_domain!r}; this is not a subdomain of {trusted_unicode!r}."
            ))
            score += 70

        if decoded != trusted_unicode and skeleton == make_skeleton(trusted_unicode):
            findings.append(Finding(
                "critical", "Trusted-domain impersonation",
                f"Its simplified visual skeleton matches {trusted_unicode!r}."
            ))
            score += 50

        # ASCII typosquatting comparisons are useful even when no IDN characters
        # are present. Limit them to explicitly trusted domains to reduce noise.
        candidate_ascii = encoded.casefold()
        trusted_ascii = ascii_hostname(trusted_unicode).casefold()
        if candidate_ascii == trusted_ascii:
            continue

        candidate_ascii_skeleton = make_ascii_skeleton(candidate_ascii)
        trusted_ascii_skeleton = make_ascii_skeleton(trusted_ascii)
        if candidate_ascii_skeleton == trusted_ascii_skeleton:
            findings.append(Finding(
                "critical", "ASCII look-alike substitution",
                f"ASCII characters or sequences visually imitate {trusted_ascii!r}."
            ))
            score += 45
            continue

        if candidate_ascii.replace("-", "") == trusted_ascii.replace("-", ""):
            findings.append(Finding(
                "high", "Hyphen manipulation",
                f"Adding or removing hyphens makes it match {trusted_ascii!r}."
            ))
            score += 35
            continue

        if is_adjacent_transposition(candidate_ascii, trusted_ascii):
            findings.append(Finding(
                "high", "Adjacent-character transposition",
                f"Two neighboring characters are reversed relative to {trusted_ascii!r}."
            ))
            score += 40
            continue

        distance = edit_distance(candidate_ascii, trusted_ascii)
        if distance <= 2:
            findings.append(Finding(
                "high" if distance == 1 else "medium",
                "ASCII typosquatting similarity",
                f"Edit distance from {trusted_ascii!r}: {distance}."
            ))
            score += 40 if distance == 1 else 25

    score = min(score, 100)
    severities = {finding.severity for finding in findings}
    verdict = (
        "high risk" if "critical" in severities or score >= 70
        else "suspicious" if "high" in severities or score >= 35
        else "low risk"
    )
    return Report(value, hostname, decoded, encoded, scripts, skeleton,
                  character_details, score, verdict, findings)


def print_report(report: Report) -> None:
    print(f"Hostname:       {report.hostname}")
    print(f"Unicode form:   {report.unicode_hostname}")
    print(f"ASCII/IDN form: {report.ascii_hostname}")
    print(f"Scripts:        {', '.join(report.scripts) or 'none'}")
    print(f"Skeleton:       {report.skeleton}")
    print(f"Risk score:     {report.risk_score}/100 ({report.verdict})")
    if report.character_details:
        print("Character evidence:")
        for item in report.character_details:
            lookalike = f"; resembles ASCII {item.looks_like}" if item.looks_like else ""
            print(
                f"  index {item.index}: {item.character!r} = {item.code_point}; "
                f"{item.unicode_name}; script={item.script}{lookalike}"
            )
    if not report.findings:
        print("Findings:       none")
    else:
        print("Findings:")
        for finding in report.findings:
            print(f"  [{finding.severity.upper()}] {finding.reason}: {finding.detail}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a URL or hostname for IDN/homoglyph warning signs."
    )
    parser.add_argument("value", help="URL or hostname to inspect")
    parser.add_argument(
        "--trusted", action="append", default=[], metavar="DOMAIN",
        help="Trusted domain to compare against; may be repeated"
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    try:
        report = analyze(args.value, args.trusted)
    except ValueError as error:
        parser.error(str(error))

    if args.json:
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
    else:
        print_report(report)
        
        
if __name__ == "__main__":
    main()
    
                   
    
