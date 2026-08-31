"""Control catalogues for PCI DSS 4.0, CIS Controls v8 and ISO/IEC 27001:2022.

**What this is, and what it is not.** These catalogues map the evidence this
platform actually produces — network findings, tracked remediation, asset
context, endpoint inventory — onto the controls of three frameworks. That
covers the technical-vulnerability part of each framework and nothing else: a
policy control, a training record or a supplier review cannot be observed by a
scanner, and a status invented for one would be a false attestation on an audit
artifact. Controls this platform cannot speak to are therefore *absent from the
catalogue* rather than present and passing.

For the same reason a control with no observable evidence in a given tenant
reports ``not_assessed`` and is excluded from the coverage score, instead of
counting as a pass. An empty estate would otherwise score 100%.

Each control names the ``signals`` (see ``signals.py``) that constitute a
failure and a ``severity_floor`` below which a finding is evidence but not a
failure — PCI's patching requirement is written about critical and high
vulnerabilities, and a control that failed on an informational banner would be
red in every tenant forever and therefore read by nobody.

Control identifiers and titles are the frameworks' own, quoted for
identification. They are references, not reproductions of the standards' text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from api.services.compliance import signals as sig

# Data a control needs before it can be assessed at all.
SOURCE_FINDINGS = "findings"
SOURCE_ASSETS = "assets"
SOURCE_ENDPOINT_INVENTORY = "endpoint_inventory"


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    # Any *one* of these signals, on evidence at or above ``severity_floor``,
    # fails the control.
    signals: tuple[str, ...] = ()
    # Conjunctions: every signal in a group must be present **on the same piece
    # of evidence**. Several controls are written about a combination rather
    # than a symptom — "an administrative service *reachable from an untrusted
    # network*" is not "an administrative service" — and folding those into
    # ``signals`` would fail PCI 1.2.1, CIS 4.6 and ISO A.8.20 in every estate
    # that runs SSH on an internal host, which is every estate. It would also
    # make PCI 11.3.2 (external scans) an exact duplicate of 11.3.1 (internal).
    combinations: tuple[tuple[str, ...], ...] = ()
    requires: tuple[str, ...] = (SOURCE_FINDINGS,)
    severity_floor: str = "low"
    # Why this platform's evidence is relevant to this control — shown in the
    # console and in the compliance report, so a reader can judge the mapping
    # rather than trust it.
    rationale: str = ""

    def __post_init__(self) -> None:
        unknown = sorted(set(self.all_signals) - set(sig.SIGNALS))
        if unknown:
            raise ValueError(f"{self.control_id}: unknown signals {unknown}")
        if not self.signals and not self.combinations:
            raise ValueError(f"{self.control_id}: a control with no signals cannot be assessed")
        for group in self.combinations:
            if len(group) < 2:
                raise ValueError(
                    f"{self.control_id}: a one-signal combination is a plain signal"
                )

    @property
    def all_signals(self) -> tuple[str, ...]:
        """Every signal this control can be failed by, in any position."""

        seen: list[str] = list(self.signals)
        for group in self.combinations:
            seen.extend(name for name in group if name not in seen)
        return tuple(seen)

    def matched_by(self, raised: set[str]) -> bool:
        """Whether one piece of evidence's signals fail this control."""

        if raised & set(self.signals):
            return True
        return any(set(group) <= raised for group in self.combinations)


@dataclass(frozen=True)
class Framework:
    framework_id: str
    name: str
    version: str
    # What the catalogue deliberately leaves out, shown next to the score so
    # "82% of PCI DSS" is never read as "82% compliant".
    scope_note: str
    controls: tuple[Control, ...] = field(default_factory=tuple)

    def control(self, control_id: str) -> Control | None:
        for entry in self.controls:
            if entry.control_id == control_id:
                return entry
        return None


_PCI_DSS_4_0 = Framework(
    framework_id="pci-dss-4.0",
    name="PCI DSS",
    version="4.0",
    scope_note=(
        "Covers the requirements a vulnerability-management platform can produce evidence "
        "for. Cardholder-data scoping, segmentation testing, policy and personnel "
        "requirements are out of scope and are not represented here."
    ),
    controls=(
        Control(
            control_id="1.2.1",
            title="Network security controls restrict traffic to that which is necessary",
            combinations=((sig.EXPOSED_ADMIN_SERVICE, sig.INTERNET_EXPOSED),),
            rationale=(
                "An administrative or database service observed on an internet-facing "
                "asset is traffic the ruleset permits and the requirement does not."
            ),
        ),
        Control(
            control_id="2.2.4",
            title="Only necessary services, protocols and daemons are enabled",
            signals=(sig.INSECURE_PROTOCOL, sig.MISCONFIGURATION),
            rationale="Cleartext and deprecated services observed on in-scope assets.",
        ),
        Control(
            control_id="2.2.7",
            title="Non-console administrative access is encrypted",
            signals=(sig.INSECURE_PROTOCOL,),
            rationale="Telnet, unencrypted management and legacy SMB observed on the estate.",
        ),
        Control(
            control_id="4.2.1",
            title="Strong cryptography protects cardholder data in transit",
            signals=(sig.WEAK_CRYPTOGRAPHY,),
            rationale="Deprecated TLS versions, weak ciphers and invalid certificates.",
        ),
        Control(
            control_id="6.3.3",
            title="Security patches are installed within the defined window",
            signals=(sig.OVERDUE_REMEDIATION,),
            severity_floor="high",
            rationale=(
                "A critical or high finding past the SLA deadline the tenant set is the "
                "same statement this requirement makes about a patch window."
            ),
        ),
        Control(
            control_id="6.4.1",
            title="Public-facing web applications are protected against known attacks",
            signals=(sig.INTERNET_EXPOSED,),
            severity_floor="high",
            rationale="Critical or high findings on services observed as internet-facing.",
        ),
        Control(
            control_id="8.3.1",
            title="Access is authenticated with strong authentication factors",
            signals=(sig.WEAK_CREDENTIALS,),
            rationale="Default, anonymous or absent authentication observed on a service.",
        ),
        Control(
            control_id="11.3.1",
            title="Internal vulnerability scans are performed and high-risk findings resolved",
            signals=(sig.UNPATCHED_CVE,),
            severity_floor="high",
            rationale=(
                "Open critical and high CVEs on the estate. The requirement is resolution, "
                "not the existence of a scan."
            ),
        ),
        Control(
            control_id="11.3.2",
            title="External vulnerability scans are performed and findings resolved",
            combinations=((sig.INTERNET_EXPOSED, sig.UNPATCHED_CVE),),
            severity_floor="high",
            rationale=(
                "Open critical and high CVEs on services observed as internet-facing. "
                "The conjunction is what keeps this from restating 11.3.1: an internal "
                "CVE is not evidence about external scanning."
            ),
        ),
        Control(
            control_id="12.5.1",
            title="An inventory of in-scope system components is maintained",
            signals=(sig.STALE_ASSET, sig.UNCLASSIFIED_ASSET),
            requires=(SOURCE_ASSETS,),
            rationale=(
                "Assets with no environment or data classification, or not observed by a "
                "recent scan, are not an inventory that can be said to be maintained."
            ),
        ),
    ),
)


_CIS_V8 = Framework(
    framework_id="cis-controls-v8",
    name="CIS Controls",
    version="8",
    scope_note=(
        "Safeguards in IG1–IG2 that this platform observes. Data recovery, security "
        "awareness, incident response and penetration-testing safeguards are out of scope."
    ),
    controls=(
        Control(
            control_id="1.1",
            title="Establish and maintain a detailed enterprise asset inventory",
            signals=(sig.STALE_ASSET,),
            requires=(SOURCE_ASSETS,),
            rationale="Assets no longer observed by scans but still carried in the registry.",
        ),
        Control(
            control_id="2.1",
            title="Establish and maintain a software inventory",
            signals=(sig.UNASSESSABLE_SOFTWARE,),
            requires=(SOURCE_ENDPOINT_INVENTORY,),
            rationale=(
                "Installed packages the matcher could not resolve to an ecosystem are "
                "inventory entries that cannot be assessed."
            ),
        ),
        Control(
            control_id="3.10",
            title="Encrypt sensitive data in transit",
            signals=(sig.WEAK_CRYPTOGRAPHY, sig.INSECURE_PROTOCOL),
            rationale="Weak TLS and cleartext protocols observed on the estate.",
        ),
        Control(
            control_id="4.1",
            title="Establish and maintain a secure configuration process",
            signals=(sig.MISCONFIGURATION,),
            rationale="Insecure configuration observed on live services.",
        ),
        Control(
            control_id="4.6",
            title="Securely manage enterprise assets and software",
            combinations=((sig.EXPOSED_ADMIN_SERVICE, sig.INTERNET_EXPOSED),),
            rationale="Management interfaces reachable from an untrusted network.",
        ),
        Control(
            control_id="5.2",
            title="Use unique passwords",
            signals=(sig.WEAK_CREDENTIALS,),
            rationale="Default or shared credentials accepted by an observed service.",
        ),
        Control(
            control_id="7.1",
            title="Establish and maintain a vulnerability management process",
            signals=(sig.UNPATCHED_CVE,),
            rationale="Open CVEs tracked against assets in this tenant.",
        ),
        Control(
            control_id="7.3",
            title="Perform automated operating system patch management",
            signals=(sig.OVERDUE_REMEDIATION,),
            severity_floor="medium",
            rationale="Findings past their remediation deadline.",
        ),
        Control(
            control_id="7.7",
            title="Remediate detected vulnerabilities",
            signals=(sig.KNOWN_EXPLOITED,),
            rationale=(
                "Vulnerabilities on the CISA KEV catalogue that are still open. Remediation "
                "priority is the safeguard's own wording."
            ),
        ),
        Control(
            control_id="12.2",
            title="Establish and maintain a secure network architecture",
            signals=(sig.INSECURE_PROTOCOL,),
            combinations=((sig.EXPOSED_ADMIN_SERVICE, sig.INTERNET_EXPOSED),),
            rationale=(
                "Legacy protocols anywhere on the network, and administrative services "
                "reachable from an untrusted one. An internal management port on its own "
                "is architecture, not a defect."
            ),
        ),
        Control(
            control_id="13.1",
            title="Centralize security event alerting",
            signals=(sig.UNOWNED_ASSET,),
            requires=(SOURCE_ASSETS,),
            rationale=(
                "An alert with no owner to route to is not centralised alerting; assets "
                "without an accountable owner are where that breaks."
            ),
        ),
    ),
)


_ISO_27001_2022 = Framework(
    framework_id="iso-27001-2022",
    name="ISO/IEC 27001",
    version="2022",
    scope_note=(
        "Annex A controls in the technological theme that this platform observes. "
        "Organizational, people and physical controls (A.5, A.6, A.7) are out of scope "
        "and are not represented here."
    ),
    controls=(
        Control(
            control_id="A.5.9",
            title="Inventory of information and other associated assets",
            signals=(sig.STALE_ASSET, sig.UNCLASSIFIED_ASSET),
            requires=(SOURCE_ASSETS,),
            rationale="Assets carried without classification or recent observation.",
        ),
        Control(
            control_id="A.5.10",
            title="Acceptable use of information and other associated assets",
            signals=(sig.UNOWNED_ASSET,),
            requires=(SOURCE_ASSETS,),
            rationale="Assets with no accountable owner.",
        ),
        Control(
            control_id="A.8.5",
            title="Secure authentication",
            signals=(sig.WEAK_CREDENTIALS,),
            rationale="Services accepting default, anonymous or absent authentication.",
        ),
        Control(
            control_id="A.8.8",
            title="Management of technical vulnerabilities",
            signals=(sig.UNPATCHED_CVE, sig.OVERDUE_REMEDIATION),
            rationale="Open CVEs and findings past their remediation deadline.",
        ),
        Control(
            control_id="A.8.9",
            title="Configuration management",
            signals=(sig.MISCONFIGURATION,),
            rationale="Insecure configuration observed on live services.",
        ),
        Control(
            control_id="A.8.19",
            title="Installation of software on operational systems",
            signals=(sig.UNASSESSABLE_SOFTWARE,),
            requires=(SOURCE_ENDPOINT_INVENTORY,),
            rationale="Installed software that the advisory matcher could not assess.",
        ),
        Control(
            control_id="A.8.20",
            title="Networks security",
            combinations=((sig.EXPOSED_ADMIN_SERVICE, sig.INTERNET_EXPOSED),),
            rationale="Administrative services reachable from an untrusted network.",
        ),
        Control(
            control_id="A.8.21",
            title="Security of network services",
            signals=(sig.INSECURE_PROTOCOL,),
            rationale="Cleartext and deprecated network services observed.",
        ),
        Control(
            control_id="A.8.23",
            title="Web filtering",
            signals=(sig.INFORMATION_DISCLOSURE,),
            rationale="Web services disclosing version, configuration or diagnostic detail.",
        ),
        Control(
            control_id="A.8.24",
            title="Use of cryptography",
            signals=(sig.WEAK_CRYPTOGRAPHY,),
            rationale="Deprecated TLS, weak ciphers and invalid certificates.",
        ),
    ),
)


FRAMEWORKS: dict[str, Framework] = {
    framework.framework_id: framework
    for framework in (_PCI_DSS_4_0, _CIS_V8, _ISO_27001_2022)
}


def get_framework(framework_id: str) -> Framework | None:
    return FRAMEWORKS.get(framework_id)


def list_frameworks() -> list[dict[str, Any]]:
    return [
        {
            "framework_id": framework.framework_id,
            "name": framework.name,
            "version": framework.version,
            "scope_note": framework.scope_note,
            "control_count": len(framework.controls),
        }
        for framework in FRAMEWORKS.values()
    ]
