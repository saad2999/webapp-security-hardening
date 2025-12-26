Fail2Ban & OSSEC monitoring templates

This folder contains templates and instructions to set up host-based real-time monitoring for the Clearway app using Fail2Ban or OSSEC.

1) Add compact log lines (done)
The app now emits compact log lines to `security.log` that are easy to parse:
 - `FAILED_LOGIN email=<email> ip=<ip> reason=<...>`
 - `SUCCESSFUL_LOGIN email=<email> ip=<ip>`
 - `ACCOUNT_LOCK email=<email> ip=<ip>` (logged when account is locked)

These appear in `security.log` via Winston and are used by Fail2Ban/OSSEC.

2) Fail2Ban (quick setup)
- Install (Debian/Ubuntu):
  sudo apt update
  sudo apt install -y fail2ban

- Copy the filter and jail templates to the system locations (requires sudo):
  sudo cp monitoring/fail2ban/clearway-auth.conf /etc/fail2ban/filter.d/clearway-auth.conf
  sudo cp monitoring/fail2ban/clearway.local /etc/fail2ban/jail.d/clearway.local

- Adjust the `logpath` inside `/etc/fail2ban/jail.d/clearway.local` to point to your running app's `security.log` if different.

- Test the filter locally:
  echo '2025-12-14T12:00:00 [warn] FAILED_LOGIN email=foo@example.com ip=1.2.3.4 reason=badpassword' >> /tmp/test-security.log
  sudo fail2ban-regex /tmp/test-security.log /etc/fail2ban/filter.d/clearway-auth.conf

- Restart and enable Fail2Ban:
  sudo systemctl restart fail2ban
  sudo systemctl enable fail2ban
  sudo fail2ban-client status clearway-auth

- Optional: create a custom action to POST alerts to a webhook (see Fail2Ban docs) or use `%(action_mwl)s` for email alerts.

3) OSSEC (HIDS)
- OSSEC/Wazuh offers host-based detection and centralized alerting. For multi-host production monitoring consider Wazuh.
- Copy `monitoring/ossec_local_rules.xml` to your OSSEC manager or agent rules directory (follow OSSEC/Wazuh docs).
- If your logs are JSON, add a decoder to extract IP/email fields.
- Configure alert forwarding (email/webhook) in the OSSEC manager.

4) Notes & recommendations
- For production, use a centralized logging stack (ELK/EFK, Datadog) and route alerts there.
- Fail2Ban's default store is in-memory; for clustered environments prefer redis-based rate limiting and centralized block lists.
- Ensure `security.log` is writable by the app and readable by Fail2Ban (or use syslog/rsyslog to forward logs to /var/log/app.log for monitoring).

If you want, I can:
 - Install (prepare) the filter/jail on the host (needs sudo access from you),
 - Add a custom Fail2Ban action that posts to a webhook and include the action file,
 - Integrate with Postfix/msmtp for email alerts and provide sample configs.
