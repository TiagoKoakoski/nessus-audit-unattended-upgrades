# stub include for local lint only — approximates legacy compat symbols
SECURITY_NOTE = 1;
SECURITY_WARNING = 2;
SECURITY_HOLE = 3;
ACT_GATHER_INFO = 1;

function script_id(id) { return TRUE; }
function script_summary(english) { return TRUE; }
function script_set_attribute(attribute, value) { return TRUE; }
function script_end_attributes() { return TRUE; }
function ssh_open_connection() { return 1; }
function ssh_close_connection(socket) { return TRUE; }
function ssh_cmd(socket, cmd) { return ""; }
function security_report_v4(port, severity, extra) { return TRUE; }
