
# REMnux YARA Rule Development and Tuning Lab

## Overview

This project documents a hands-on YARA rule development and threat-detection lab performed in REMnux.

The objective was to learn how YARA rules are created, tested, validated, and tuned to reduce false positives while investigating suspicious files.

> **Lab Safety:** All files and indicators used in this project were harmless simulated data created specifically for testing.

## Lab Environment

- REMnux Linux
- YARA
- GNU Nano
- Linux command line
- SHA-256 hashing

## Skills Demonstrated

- YARA rule creation
- String-based detection
- Multi-indicator detection
- Case-insensitive matching with `nocase`
- Recursive directory scanning
- False-positive identification
- YARA rule tuning
- Detection validation
- SHA-256 collection
- SOC/XDR investigation methodology

## YARA Rule Development

I developed a YARA rule using PowerShell-related indicators:

```yara
rule My_First_YARA_Rule
{
    strings:
        $a = "powershell" nocase
        $b = "Invoke-WebRequest" nocase
        $c = "cmd.exe" nocase

    condition:
        2 of them
}
```

The rule required at least two indicators to be present before generating a match.

## Detection Testing

A controlled test file containing `PowerShell` and `Invoke-WebRequest` was scanned using:

```bash
yara -s basic-yara suspicious-test.txt
```

YARA successfully identified both matching strings.

## Recursive Directory Scanning

I then tested the rule against multiple files using:

```bash
yara -r -s basic-yara yara-lab/
```

This demonstrated how YARA can search a collection of files rather than analyzing files individually.

## False-Positive Testing

A harmless administrative test file containing `PowerShell` and `cmd.exe` also triggered the original rule.

This demonstrated an important detection-engineering principle:

> A YARA match is an investigative lead, not automatic proof that a file is malicious.

## Rule Tuning

To reduce the false positive, I changed the condition to:

```yara
condition:
    $b and ($a or $c)
```

This required `Invoke-WebRequest` to be present together with either `PowerShell` or `cmd.exe`.

After rescanning the directory, the harmless administrative file no longer triggered while the suspicious test file continued to match.

## SHA-256 Investigation Artifact

After detecting the suspicious test file, I generated its SHA-256 hash:

```bash
sha256sum yara-lab/suspicious-test.txt
```

In a real SOC environment, the hash could then be searched in an EDR/XDR platform to investigate:

- Which endpoints contain the file
- Whether the file executed
- Parent and child processes
- Associated user activity
- Related network connections
- Whether the same hash appears on other systems

## Investigation Workflow

The lab demonstrated the following workflow:

**YARA Detection → Validate Match → Identify False Positives → Tune Rule → Retest → Collect SHA-256 → Correlate with XDR/EDR Telemetry**

## Key Takeaway

This project demonstrated that effective YARA detection is not simply about producing a match. Detection rules must be tested against both suspicious and benign data, evaluated for false positives, tuned, and validated again.

## Portfolio Documentation

A complete lab report containing screenshots and step-by-step evidence is included in this repository.

## Disclaimer

This project was completed in an isolated REMnux lab using harmless simulated files and indicators for educational purposes.
