# SSH Traffic Monitor & Analyzer

A Python-based Linux tool for monitoring network activity associated with authorized SSH sessions and generating structured JSON reports for further analysis.

> **Important:** This tool observes network metadata. It cannot reliably prove that a person actively interacted with an application, and its results must not be treated as definitive evidence of user behavior. Use it only on systems and sessions you own or are explicitly authorized to monitor.

## Overview

This project demonstrates how network metadata can be collected and summarized during an authorized SSH-based monitoring session.

The script combines active TCP connection inspection, DNS responses, TLS Server Name Indication (SNI), reverse DNS lookups, and predefined IP ranges to classify some network destinations into application or service categories.

It can produce:
- A live console view of detected services and destination IPs.
- A JSON report containing monitoring metadata, connection statistics, classified services, and a chronological event log.
- Summary metrics for SSH connection duration and estimated network activity.

## Repository layout

```text
ssh-traffic-analyzer/
├── README.md
├── user_monitor.py
├── LICENSE
├── .gitignore
└── docs/
    ├── setup-and-usage.md
    └── fa/
        └── README.md
```

## Requirements

- A compatible Linux server, such as a supported Ubuntu release.
- Python 3.
- `tshark`, `iproute2`, and `dnsutils`.
- `tmux` if you want the monitoring process to continue after detaching from the terminal.
- Administrative privileges for packet capture and access to the relevant process/socket information.
- Explicit authorization to monitor the account and network traffic in question.

The current script imports Python standard-library modules. The listed packages are system tools rather than Python packages.

## Quick start

1. Review the script and this documentation before running anything.
2. Prepare an SSH account on a server you administer.
3. Install the required system packages (see [Setup and usage](docs/setup-and-usage.md)).
4. Place `user_monitor.py` in your working directory.
5. Run the monitor for an account and duration you are authorized to monitor.

Example duration formats accepted by the script include `30m`, `2h30m`, and `12h`.

The script accepts optional command-line arguments:

```bash
sudo python3 user_monitor.py USERNAME 30m
```

If you omit the arguments, it prompts for a username and duration. Run it only after reviewing its privileges and capture behavior. Depending on the environment, `tshark` may require elevated privileges.

## Connecting through SSH

A user may establish an SSH connection to a VPS using an SSH client on their operating system. Examples include a terminal SSH client on Linux, macOS, or Windows, or a compatible mobile SSH tunneling application.

Client configuration and VPN/tunnel behavior depend on the application. This repository does not configure a full VPN server by itself; it observes selected network metadata on the Linux host. Confirm that your SSH setup routes the traffic you intend to study and that you have permission to inspect it.

## Running in tmux

Install `tmux` if it is not already available:

```bash
sudo apt update
sudo apt install -y tmux
```

Create a session:

```bash
tmux new -s monitor
```

Start the script inside that session:

```bash
sudo python3 user_monitor.py USERNAME 2h30m
```

Detach while leaving the session running with `Ctrl+B`, then `D`. Reattach later with:

```bash
tmux attach -t monitor
```

If the session has already ended, `tmux attach` will not restart the script.

## Reports

The script writes a JSON report in its current working directory. The filename includes the monitored username and the start timestamp. It autosaves periodically and writes a final report when it stops.

Reports may contain usernames, timestamps, domains, destination IP addresses, and behavioral patterns. Keep them private, set appropriate permissions, and remove or redact them before sharing. JSON reports are ignored by Git by default through `.gitignore`.

## Analyze a report with an LLM

You can provide a report to a language model together with the English prompt in [the setup guide](docs/setup-and-usage.md#analyzing-the-json-report). Remove or mask personal information and sensitive network details first.

An LLM can help organize and interpret observed metadata, but it cannot infer direct user interaction reliably from this report alone. Treat its classifications and duration estimates as hypotheses to validate, not as ground truth.

## Technical limitations

- The packet-capture thread listens on the `any` interface. DNS and SNI observations may include traffic not attributable to the SSH account being monitored.
- Domain and IP classification is heuristic. Shared infrastructure, CDNs, encrypted DNS, encrypted client hello, QUIC, VPNs, and changing provider IP ranges can reduce accuracy.
- A detected destination does not prove that a user opened or actively used a particular application.
- The current duration calculation estimates activity based on observed connections and classification events; it does not measure screen focus, taps, keystrokes, or time spent reading content.
- The current code should be reviewed and tested before being used for operational, investigative, or evidentiary purposes.

## Privacy and authorized use

Use this project only on systems and network sessions you own or are explicitly authorized to monitor. Obtain informed consent where required by law or policy. Do not use it for covert surveillance or unauthorized collection of another person's activity.

Limit access to captured data, avoid publishing real reports, and define an appropriate retention period.

## Contributing

Bug reports, documentation improvements, and carefully tested changes are welcome. Do not include credentials, private user identifiers, real monitoring reports, or sensitive network inventories in issues and pull requests.

## License

No license is granted until a license file is selected and added. See the repository's `LICENSE` file before reusing or redistributing the project.
