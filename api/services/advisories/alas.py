"""Amazon Linux binary RPM fix statements from core updateinfo metadata."""
from api.services.advisories.rpm import RpmAdvisoryProvider


class AlasAdvisoryProvider(RpmAdvisoryProvider):
    name = "amazon-alas"
    distro = "amazonlinux"
    env_var = "OCTO_ALAS_ADVISORY_DATABASE"
    default_path = "scanner/data/advisories/alas-advisories.json"
