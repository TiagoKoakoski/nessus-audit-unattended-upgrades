#
# Plugin custom -- Unattended Upgrades nao instalado/configurado/rodando
#
# Replica a MESMA logica ja validada em unattended_upgrades_combined.audit
# (incluindo as duas correcoes achadas em teste real em 2026-11-06, hosts
# host-debian-teste e host-rocky-teste -- ver README.md), mas reportado como
# VULNERABILIDADE normal (aba Vulnerabilities) em vez de Compliance,
# a pedido explicito: precisa aparecer junto com as demais vulnerabilidades.
#
# IMPORTANTE -- NAO validado em scan real ainda. Diferente do .audit (que
# foi testado campo a campo via SSH manual antes de subir), este arquivo
# so foi escrito com base na logica ja comprovada do .audit -- precisa do
# mesmo ciclo de validacao: rodar `nasl -t unattended_upgrades_plugin.nasl`
# se tiver o binario nasl disponivel, e/ou rodar um scan isolado nos hosts
# ja validados (host-debian-teste, host-rocky-teste) comparando o resultado com o
# que ja sabemos ser verdade, ANTES de soltar na base toda.
#
# Plugin ID 900001 -- faixa reservada para plugins customizados/privados,
# fora da faixa usada pelo feed oficial do Tenable. Confirme dentro do
# proprio Tenable.sc se ha orientacao especifica de faixa antes de subir.
#

#%NASL_MIN_LEVEL 80900

include("compat.inc");

if (description)
{
  script_id(900001);
  script_version("1.0");
  script_name(english:"Unattended Upgrades Not Installed/Configured/Running");
  script_summary(english:"Checks if automatic OS security updates are installed, configured and actively running (unattended-upgrades / dnf-automatic / yum-cron)");

  script_set_attribute(attribute:"synopsis", value:"The remote host may not be receiving automatic security updates.");
  script_set_attribute(attribute:"description", value:
"The remote host does not appear to have automatic security updates
properly installed, configured and actively running -- checked via
unattended-upgrades (Debian/Ubuntu), dnf-automatic (RHEL/CentOS 8+,
Rocky, Alma, Stream) or yum-cron (RHEL/CentOS 7, legado), conforme o
sistema operacional detectado.

This increases the risk that the host is missing recently released
security patches.");
  script_set_attribute(attribute:"solution", value:
"Install and enable the automatic update mechanism appropriate for the
host's OS (unattended-upgrades, dnf-automatic or yum-cron), make sure
it is configured to actually apply updates (not just download/notify),
and confirm via logs/journal that it has run recently.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"Copyright (C) 2026 Internal");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("ssh_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

sock = ssh_open_connection();
if (!sock) exit(1, "Could not open an SSH connection.");

function run(cmd)
{
  local_var out;
  out = ssh_cmd(socket:sock, cmd:cmd);
  if (isnull(out)) out = "";
  return out;
}

findings = make_list();

os_release = run(cmd:"cat /etc/os-release 2>/dev/null");

is_debian = ("ID=debian" >< os_release || "ID=ubuntu" >< os_release);

if (is_debian)
{
  os_family_label = "Debian/Ubuntu (unattended-upgrades)";

  pkg = run(cmd:"dpkg-query -W -f='${Status}\n' unattended-upgrades 2>/dev/null");
  if ("install ok installed" >!< pkg)
    findings = make_list(findings, "unattended-upgrades package is not installed");

  cfg = run(cmd:"cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null");
  if (!egrep(pattern:'APT::Periodic::Unattended-Upgrade +"(1|always)";', string:cfg))
    findings = make_list(findings, 'Automatic unattended upgrades are not enabled in /etc/apt/apt.conf.d/20auto-upgrades (needs "1" or "always")');

  timer_enabled = chomp(run(cmd:"systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null"));
  if (timer_enabled != "enabled")
    findings = make_list(findings, "apt-daily-upgrade.timer is not enabled");

  timer_active = chomp(run(cmd:"systemctl is-active apt-daily-upgrade.timer 2>/dev/null"));
  if (timer_active != "active")
    findings = make_list(findings, "apt-daily-upgrade.timer is not active");

  log_evidence = run(cmd:"find /var/log/unattended-upgrades/unattended-upgrades.log -mtime -30 2>/dev/null");
  if ("unattended-upgrades.log" >!< log_evidence)
    findings = make_list(findings, "No evidence unattended-upgrades actually ran in the last 30 days");
}
else
{
  redhat_family = run(cmd:"test -f /etc/redhat-release && echo REDHAT_FAMILY_FOUND || echo REDHAT_FAMILY_NOT_FOUND");

  if ("REDHAT_FAMILY_FOUND" >< redhat_family)
  {
    is_el7 = ('VERSION_ID="7' >< os_release);

    if (is_el7)
    {
      os_family_label = "RHEL/CentOS 7 (yum-cron, legado)";

      pkg = run(cmd:"rpm -q --quiet yum-cron && echo PKG_PRESENT || echo PKG_ABSENT");
      if ("PKG_PRESENT" >!< pkg)
        findings = make_list(findings, "yum-cron package is not installed");

      yumcron_cfg = run(cmd:"cat /etc/yum/yum-cron.conf 2>/dev/null");
      if (!egrep(pattern:"^\\s*download_updates\\s*=\\s*yes", string:yumcron_cfg))
        findings = make_list(findings, "yum-cron.conf: download_updates is not set to yes");
      if (!egrep(pattern:"^\\s*apply_updates\\s*=\\s*yes", string:yumcron_cfg))
        findings = make_list(findings, "yum-cron.conf: apply_updates is not set to yes");

      yumcron_enabled = run(cmd:"if systemctl is-enabled yum-cron 2>/dev/null | grep -qx enabled; then echo YUMCRON_ENABLED; elif test -x /etc/cron.daily/0yum-daily.cron; then echo YUMCRON_ENABLED; else echo YUMCRON_NOT_ENABLED; fi");
      if ("YUMCRON_ENABLED" >!< yumcron_enabled)
        findings = make_list(findings, "yum-cron is not enabled to run (neither systemd service nor /etc/cron.daily/0yum-daily.cron)");

      yumcron_recent = run(cmd:"test \"$(journalctl -u yum-cron --since '-30 days' --no-pager 2>/dev/null | wc -l)\" -gt 0 && echo RECENT_RUN_FOUND || echo NO_RECENT_RUN");
      if ("RECENT_RUN_FOUND" >!< yumcron_recent)
        findings = make_list(findings, "No evidence yum-cron actually ran in the last 30 days");
    }
    else
    {
      os_family_label = "RHEL/CentOS 8+/Stream/Rocky/Alma (dnf-automatic)";

      pkg = run(cmd:"rpm -q --quiet dnf-automatic && echo PKG_PRESENT || echo PKG_ABSENT");
      if ("PKG_PRESENT" >!< pkg)
        findings = make_list(findings, "dnf-automatic package is not installed");

      dnf_cfg = run(cmd:"cat /etc/dnf/automatic.conf 2>/dev/null");
      if (!egrep(pattern:"^\\s*apply_updates\\s*=\\s*yes", string:dnf_cfg))
        findings = make_list(findings, "automatic.conf: apply_updates is not set to yes");

      dnf_timer_enabled = run(cmd:"if systemctl is-enabled dnf-automatic-install.timer 2>/dev/null | grep -qx enabled || systemctl is-enabled dnf-automatic.timer 2>/dev/null | grep -qx enabled; then echo TIMER_ENABLED; else echo TIMER_NOT_ENABLED; fi");
      if ("TIMER_ENABLED" >!< dnf_timer_enabled)
        findings = make_list(findings, "Neither dnf-automatic-install.timer nor dnf-automatic.timer is enabled");

      dnf_timer_active = run(cmd:"if systemctl is-active dnf-automatic-install.timer 2>/dev/null | grep -qx active || systemctl is-active dnf-automatic.timer 2>/dev/null | grep -qx active; then echo TIMER_ACTIVE; else echo TIMER_NOT_ACTIVE; fi");
      if ("TIMER_ACTIVE" >!< dnf_timer_active)
        findings = make_list(findings, "Neither dnf-automatic-install.timer nor dnf-automatic.timer is active");

      dnf_recent = run(cmd:"test \"$(journalctl -u dnf-automatic-install.service -u dnf-automatic.service --since '-30 days' --no-pager 2>/dev/null | wc -l)\" -gt 0 && echo RECENT_RUN_FOUND || echo NO_RECENT_RUN");
      if ("RECENT_RUN_FOUND" >!< dnf_recent)
        findings = make_list(findings, "No evidence dnf-automatic actually ran in the last 30 days (check journald retention if everything else passes)");
    }
  }
  else
  {
    ssh_close_connection();
    exit(0, "OS not recognized as Debian/Ubuntu or RHEL/CentOS family -- plugin does not apply.");
  }
}

ssh_close_connection();

if (max_index(findings) > 0)
{
  report = "Detected OS family: " + os_family_label + "\n\n";
  report += "The following automatic-security-update issues were found:\n\n";
  foreach f (findings) report += " - " + f + "\n";
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else
{
  exit(0, "Automatic security updates (" + os_family_label + ") appear properly installed, configured and running.");
}
