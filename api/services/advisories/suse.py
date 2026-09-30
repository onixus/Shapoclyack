"""SUSE Linux Enterprise Server binary RPM fix statements from CSAF."""
from api.services.advisories.rpm import RpmAdvisoryProvider


class SuseAdvisoryProvider(RpmAdvisoryProvider):
    name = "suse-csaf"
    distro = "sles"
    env_var = "OCTO_SUSE_ADVISORY_DATABASE"
    default_path = "scanner/data/advisories/suse-advisories.json"
