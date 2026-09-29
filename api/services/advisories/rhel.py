"""Red Hat binary RPM fix statements, imported from explicitly bound CSAF."""
from api.services.advisories.rpm import RpmAdvisoryProvider


class RhelAdvisoryProvider(RpmAdvisoryProvider):
    name = "redhat-csaf"
    distro = "rhel"
    env_var = "OCTO_RHEL_ADVISORY_DATABASE"
    default_path = "scanner/data/advisories/rhel-advisories.json"
