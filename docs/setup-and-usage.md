# Setup and Usage

This guide describes a basic VPS/SSH setup and how to run `user_monitor.py`. Use only a server and network sessions you own or are explicitly authorized to monitor.

## 1. Prepare a VPS

You need a Linux VPS that you administer. Apply normal server hardening, keep the operating system updated, and use SSH authentication appropriate for your environment.

## 2. Create a dedicated Linux account

On Ubuntu, create an account by replacing `MONITORED_USERNAME` with a username you choose:

```bash
sudo useradd -m -s /bin/bash MONITORED_USERNAME
sudo passwd MONITORED_USERNAME
```

The `passwd` command prompts you to set a password. Do not put passwords in shell history, documentation, source code, or Git commits. Consider SSH keys and a restricted account where practical.

## 3. Connect using an SSH client

The account holder can connect to the VPS using an SSH client compatible with their device. On Linux, macOS, and Windows, a terminal client may be used. On Android or iOS, use a reputable SSH client that supports the connection mode you need.

Enter the VPS hostname or IP address and the authorized account's credentials or SSH key. Client-specific setup varies. An SSH connection is not automatically a full VPN: routing all device traffic through the VPS depends on the client and server configuration. This monitoring script does not set up that routing for you.

## 4. Install system dependencies

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y tshark python3 whois dnsutils iproute2 tmux
```

The current script directly invokes `tshark` and standard Linux utilities. `whois` and `iproute2` are included as useful network troubleshooting tools; the current source may not call every installed package. `tmux` is used to keep a terminal session attached to a running process.

During installation, `tshark` may ask whether non-superusers should be allowed to capture packets. Review that choice according to your security policy. The examples below use `sudo` to run the script.

## 5. Place and review the script

Put `user_monitor.py` in a working directory on the VPS. Review the code before running it, especially its packet-capture behavior and the data it writes to disk.

Check that the target Linux account exists:

```bash
id MONITORED_USERNAME
```

## 6. Run the monitor

Start a tmux session:

```bash
tmux new -s monitor
```

Then run the monitor, replacing the example username and duration:

```bash
sudo python3 user_monitor.py MONITORED_USERNAME 2h30m
```

Supported duration examples include:

- `30m` — 30 minutes
- `2h30m` — 2 hours and 30 minutes
- `12h` — 12 hours

You can also run `sudo python3 user_monitor.py` without arguments and answer the prompts.

To detach from tmux while leaving the session running, press `Ctrl+B`, release the keys, then press `D`.

To return to the session:

```bash
tmux attach -t monitor
```

To list tmux sessions:

```bash
tmux ls
```

Detaching does not stop the process. The script normally exits when its requested duration ends, or when it receives Ctrl+C in the attached terminal.

## 7. Find the JSON report

The report is saved in the script's current working directory. The filename includes the monitored username and start time, for example:

```text
MONITORED_USERNAME_YYYY-MM-DD_HH-MM-SS.json
```

The script periodically saves the report and writes a final report when it finishes. The JSON may include usernames, timestamps, observed domains, destination IPs, and usage estimates. Treat it as sensitive and do not commit it to a public repository.

## 8. Analyzing the JSON report

Before uploading a report to an LLM, redact usernames, public IP addresses, private hostnames, and any other information that could identify a person or infrastructure. Do not upload data unless you have permission to share it with that service.

Copy the following English prompt and attach the sanitized JSON report:

> You are a specialist in network data analysis and digital forensics. I will provide a JSON file containing network/VPN usage logs from my own device over a specified time window. Analyze the data carefully and produce a structured report in Persian, following the requirements below.
>
> ### 1. Separate actual user activity from background processes
>
> - Do not classify system traffic, operating-system updates, package managers (such as npmjs or background developer-package activity), infrastructure domains, or development tools (such as Playwright, VS Code extensions, and Windows/macOS update services) as active web browsing or direct user presence. Separate them into a background/system activity category unless the evidence supports direct user interaction.
> - Be careful when interpreting shared infrastructure. For example, traffic to Facebook or Meta servers does not necessarily mean that the user visited Facebook; it could be related to Instagram, WhatsApp, or another service using shared infrastructure. Base conclusions on the strongest available application-level evidence and clearly state uncertainty.
>
> ### 2. Application and website duration breakdown
>
> - Provide a service-by-service list of observed applications and websites, with durations formatted in minutes and seconds where the data supports such estimates.
> - Examples include Telegram, Instagram, WhatsApp, Snapp, and Torob. Include only services supported by the evidence in the report; do not invent activity for services that were not observed.
> - Do not count background traffic or developer tools as active user time unless direct interaction is independently established. If the logs cannot establish direct interaction, label the value as an estimated period of classified network activity rather than confirmed user activity.
>
> ### 3. Final statistics and timeline
>
> End the report with a concise statistical summary that includes:
>
> - The monitoring start and end times.
> - The periods during which activity was observed, distinguishing them from periods when the device was merely connected.
> - The total estimated duration of classified activity, clearly stating the limitations of this estimate.
> - The most frequently observed or longest-duration service, distinguishing measured results from uncertain attribution.
>
> ### Reporting requirements
>
> - Process the supplied JSON and write the final report in Persian.
> - Use clear headings, tables, and time formats.
> - Separate observations, estimates, and inferences.
> - Do not claim that network metadata proves a person was actively looking at a screen or interacting with an application.
> - Explicitly identify missing data, possible false positives, shared infrastructure, and other limitations.
> - Do not fabricate timestamps, applications, durations, or conclusions that are not supported by the supplied data.

## Important interpretation note

The current script's `usage_seconds` values are estimates generated by its connection/event logic. They are not reliable measurements of active screen time. In particular, the packet-capture thread listens on all interfaces, so some DNS/SNI observations may not belong to the account being monitored. Any final report must preserve this uncertainty.
