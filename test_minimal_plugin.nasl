#%NASL_MIN_LEVEL 80900

include("compat.inc");

if (description)
{
  script_id(900002);
  script_version("1.0");
  script_name(english:"Custom Plugin Pipeline Test");
  script_summary(english:"Minimal test plugin to validate the custom plugin upload pipeline");

  script_set_attribute(attribute:"synopsis", value:"Test plugin, no real check.");
  script_set_attribute(attribute:"description", value:"Minimal plugin used only to validate that the custom NASL upload pipeline accepts and registers a plugin.");
  script_set_attribute(attribute:"solution", value:"N/A - test plugin, safe to remove.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"Copyright (C) 2026 Internal");

  exit(0);
}

exit(0, "Test plugin ran successfully.");
