"""Control catalogues: PCI DSS 4.0, CIS Controls v8, ISO/IEC 27001:2022, and
the Russian regulators — FSTEC orders 117 (state information systems), 21
(personal data) and 239 (critical information infrastructure), and
GOST R 57580.1-2017 (financial organisations, Bank of Russia).

**What this is, and what it is not.** These catalogues map the evidence this
platform actually produces — network findings, tracked remediation, asset
context, endpoint inventory — onto the controls of each framework. That
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
The Russian catalogues keep the regulators' own Russian measure codes and
titles for the same reason: an auditor looks for «АНЗ.1», not for a
translation of it.

**The Russian catalogues and the regulator's clock.** FSTEC's vulnerability
management guidance of 17 May 2023 sets remediation windows by criticality
level (24 hours, 7 days, 4 weeks, 4 months), and the 2026 methodological
document under order 117 defers to the same. Those windows are a fact about
the regulator, not about the tenant, so the Russian controls written about
"оперативное устранение" use ``overdue_fstec_window`` — computed from the
regulator's figures — rather than ``overdue_remediation``, which is the
tenant's own SLA. A tenant that set itself 30 days for a critical finding is
inside its SLA and outside the regulator's window, and an audit page has to
say the second thing. The platform's CVSS-derived severity stands in for the
guidance's own criticality level, which is assigned by a separate FSTEC
method; the scope notes say so.
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


# ---------------------------------------------------------------------------
# Russian regulators
# ---------------------------------------------------------------------------

# Every exposure-shaped control below pairs the observation with the
# exposure, for the reason given on PCI 1.2.1: «управление информационными
# потоками» is not failed by an internal SSH port.
_ADMIN_FROM_UNTRUSTED = (sig.EXPOSED_ADMIN_SERVICE, sig.INTERNET_EXPOSED)
_CLEARTEXT_FROM_UNTRUSTED = (sig.INSECURE_PROTOCOL, sig.INTERNET_EXPOSED)
_WEAK_AUTH_FROM_UNTRUSTED = (sig.WEAK_CREDENTIALS, sig.INTERNET_EXPOSED)


_FSTEC_117 = Framework(
    framework_id="fstec-117",
    name="ФСТЭК № 117 (ГИС)",
    version="2025",
    scope_note=(
        "Приказ ФСТЭК России от 11.04.2025 № 117 (в силе с 01.03.2026, заменил приказ "
        "№ 17) и методический документ «Состав и содержание мероприятий и мер по защите "
        "информации, содержащейся в информационных системах» от 12.04.2026. В каталоге — "
        "мероприятия и меры, по которым у платформы есть наблюдаемые свидетельства: "
        "управление уязвимостями и обновлениями, контроль конфигураций, сегментация, "
        "защита каналов, аутентификация. Классы защищённости, моделирование угроз, "
        "документирование, ГосСОПКА, физическая защита и организационные мероприятия "
        "не представлены. Уровень опасности уязвимости по методике ФСТЭК заменён "
        "серьёзностью находки по CVSS."
    ),
    controls=(
        Control(
            control_id="КК",
            title="Контроль конфигураций информационных систем (п. 3.2)",
            signals=(sig.MISCONFIGURATION, sig.INSECURE_PROTOCOL),
            rationale=(
                "Insecure configuration and legacy protocols observed on live services are "
                "departures from the configuration standard the measure requires."
            ),
        ),
        Control(
            control_id="КУ",
            title="Управление уязвимостями (п. 3.3)",
            signals=(sig.UNPATCHED_CVE, sig.KNOWN_EXPLOITED),
            severity_floor="high",
            rationale=(
                "Open critical and high CVEs, and anything on the CISA KEV catalogue: the "
                "measure is identification and remediation, and an open high-criticality "
                "vulnerability is the remediation half not done. The same reading as "
                "21 АНЗ.1 and 239 АУД.2; the windows are КУ-сроки."
            ),
        ),
        Control(
            control_id="КУ-сроки",
            title="Сроки устранения уязвимостей по уровню критичности (п. 3.3)",
            signals=(sig.OVERDUE_FSTEC_WINDOW,),
            rationale=(
                "An open finding older than the FSTEC window for its level (24 h critical, "
                "7 d high, 4 w medium, 4 m low). Measured on the regulator's clock, not the "
                "tenant's SLA."
            ),
        ),
        Control(
            control_id="КО",
            title="Управление обновлениями (п. 3.4)",
            signals=(sig.OVERDUE_REMEDIATION,),
            rationale=(
                "A finding past the deadline the operator's own regulation sets. The measure "
                "leaves the update window to the operator's internal regulation, which is "
                "what the tenant's SLA policy is."
            ),
        ),
        Control(
            control_id="ОД",
            title="Защита информации ограниченного доступа (п. 3.5)",
            signals=(sig.UNCLASSIFIED_ASSET,),
            requires=(SOURCE_ASSETS,),
            rationale=(
                "The measure starts with a list of restricted information and the systems "
                "that hold it; an asset with neither an environment nor a data "
                "classification is one nobody has placed on or off that list."
            ),
        ),
        Control(
            control_id="ПК",
            title="Периодический контроль уровня защищённости (п. 3.19)",
            signals=(sig.STALE_ASSET,),
            requires=(SOURCE_ASSETS,),
            rationale=(
                "An asset the registry carries but no recent scan has observed is outside "
                "the periodic control the measure requires."
            ),
        ),
        Control(
            control_id="ИАФ.3",
            title="Аутентификация пользователей",
            signals=(sig.WEAK_CREDENTIALS,),
            rationale="Services accepting default, anonymous or absent authentication.",
        ),
        Control(
            control_id="МСЭ.3",
            title="Контроль сетевого доступа и фильтрация трафика",
            combinations=(_ADMIN_FROM_UNTRUSTED, _CLEARTEXT_FROM_UNTRUSTED),
            rationale=(
                "An administrative or cleartext service observed as internet-facing is "
                "traffic the boundary filter permits and the measure does not."
            ),
        ),
        Control(
            control_id="МСЭ.4",
            title="Маскирование системы",
            signals=(sig.INFORMATION_DISCLOSURE,),
            rationale=(
                "Version, banner and diagnostic disclosure is exactly the configuration "
                "detail the measure requires to be hidden from an external observer."
            ),
        ),
        Control(
            control_id="ЗКС.1",
            title="Защита данных при передаче по каналам связи",
            signals=(sig.WEAK_CRYPTOGRAPHY, sig.INSECURE_PROTOCOL),
            rationale="Deprecated TLS, weak ciphers, invalid certificates and cleartext services.",
        ),
        Control(
            control_id="ЗКУ.2",
            title="Обеспечение целостности программного обеспечения конечных устройств",
            signals=(sig.UNASSESSABLE_SOFTWARE,),
            requires=(SOURCE_ENDPOINT_INVENTORY,),
            rationale=(
                "Installed packages the advisory matcher could not resolve are software on "
                "an endpoint whose provenance and state cannot be vouched for."
            ),
        ),
    ),
)


_FSTEC_21 = Framework(
    framework_id="fstec-21",
    name="ФСТЭК № 21 (ИСПДн)",
    version="2013",
    scope_note=(
        "Приказ ФСТЭК России от 18.02.2013 № 21 — состав мер по обеспечению безопасности "
        "персональных данных (152-ФЗ). В каталоге — меры групп ИАФ, УПД, ОПС, АНЗ и ЗИС, "
        "для которых есть свидетельства сканирования и инвентаря. Уровень защищённости "
        "ПДн (УЗ-1…УЗ-4), выбор и адаптация базового набора, обязанности оператора по "
        "152-ФЗ (согласия, локализация, уведомление Роскомнадзора) и организационные "
        "меры не представлены. ФСТЭК опубликовала проект приказа на замену № 21 с "
        "01.09.2026 — каталог будет перепривязан, когда его текст станет окончательным."
    ),
    controls=(
        Control(
            control_id="ИАФ.4",
            title="Управление средствами аутентификации",
            signals=(sig.WEAK_CREDENTIALS,),
            rationale=(
                "A default or absent password is an authenticator that was never "
                "initialised, which is the measure's own subject."
            ),
        ),
        Control(
            control_id="УПД.3",
            title="Управление информационными потоками между устройствами и сегментами",
            combinations=(_ADMIN_FROM_UNTRUSTED,),
            rationale="Administrative or database services reachable from an untrusted network.",
        ),
        Control(
            control_id="УПД.13",
            title="Реализация защищённого удалённого доступа через внешние сети",
            combinations=(_CLEARTEXT_FROM_UNTRUSTED, _WEAK_AUTH_FROM_UNTRUSTED),
            rationale=(
                "A cleartext or weakly authenticated service observed as internet-facing is "
                "remote access that is not protected."
            ),
        ),
        Control(
            control_id="ОПС.3",
            title="Установка только разрешённого к использованию программного обеспечения",
            signals=(sig.UNASSESSABLE_SOFTWARE,),
            requires=(SOURCE_ENDPOINT_INVENTORY,),
            rationale=(
                "Installed packages the matcher could not resolve to an ecosystem cannot be "
                "shown to be on the permitted list."
            ),
        ),
        Control(
            control_id="АНЗ.1",
            title="Выявление, анализ и оперативное устранение уязвимостей",
            signals=(sig.UNPATCHED_CVE, sig.KNOWN_EXPLOITED),
            severity_floor="high",
            rationale=(
                "Open critical and high CVEs, and anything on the CISA KEV catalogue: the "
                "same reading of «известные уязвимости» as 117 КУ and 239 АУД.2."
            ),
        ),
        Control(
            control_id="АНЗ.2",
            title="Контроль установки обновлений программного обеспечения",
            signals=(sig.OVERDUE_REMEDIATION, sig.OVERDUE_FSTEC_WINDOW),
            rationale=(
                "A finding past the operator's own deadline or past the FSTEC window for "
                "its level: an update not installed on either clock."
            ),
        ),
        Control(
            control_id="АНЗ.3",
            title="Контроль параметров настройки и правильности функционирования ПО и СЗИ",
            signals=(sig.MISCONFIGURATION,),
            rationale="Insecure configuration observed on live services.",
        ),
        Control(
            control_id="АНЗ.4",
            title="Контроль состава технических средств, программного обеспечения и СЗИ",
            signals=(sig.STALE_ASSET,),
            requires=(SOURCE_ASSETS,),
            rationale=(
                "Assets no longer observed by a scan but still carried are a composition "
                "that is not under control. The software half is ОПС.3, which needs the "
                "endpoint inventory this control does not."
            ),
        ),
        Control(
            control_id="АНЗ.5",
            title="Контроль правил генерации и смены паролей, учётных записей и полномочий",
            signals=(sig.WEAK_CREDENTIALS,),
            rationale="Default, shared or absent credentials accepted by an observed service.",
        ),
        Control(
            control_id="ЗИС.3",
            title="Защита информации при передаче по каналам связи за пределы контролируемой зоны",
            signals=(sig.WEAK_CRYPTOGRAPHY, sig.INSECURE_PROTOCOL),
            rationale="Deprecated TLS, weak ciphers, invalid certificates and cleartext services.",
        ),
        Control(
            control_id="ЗИС.17",
            title="Сегментирование информационной системы и защита периметров сегментов",
            combinations=(_ADMIN_FROM_UNTRUSTED,),
            rationale="Management and datastore interfaces reachable across the perimeter.",
        ),
    ),
)


_FSTEC_239 = Framework(
    framework_id="fstec-239",
    name="ФСТЭК № 239 (КИИ)",
    version="2017",
    scope_note=(
        "Приказ ФСТЭК России от 25.12.2017 № 239 — требования по обеспечению безопасности "
        "значимых объектов КИИ (187-ФЗ). В каталоге — меры групп АУД, ОПО, УКФ, ИАФ, УПД и "
        "ЗИС, наблюдаемые платформой. Категория значимости объекта, состав базового "
        "набора по категории, взаимодействие с ГосСОПКА, реагирование на инциденты и "
        "организационные меры не представлены. Уровень опасности уязвимости по методике "
        "ФСТЭК заменён серьёзностью находки по CVSS."
    ),
    controls=(
        Control(
            control_id="АУД.1",
            title="Инвентаризация информационных ресурсов",
            signals=(sig.STALE_ASSET, sig.UNCLASSIFIED_ASSET),
            requires=(SOURCE_ASSETS,),
            rationale=(
                "Assets carried without classification or without recent observation are "
                "not an inventory that can be said to be maintained."
            ),
        ),
        Control(
            control_id="АУД.2",
            title="Анализ уязвимостей и их устранение",
            signals=(sig.UNPATCHED_CVE, sig.KNOWN_EXPLOITED),
            severity_floor="high",
            rationale=(
                "Open critical and high CVEs, and anything on the CISA KEV catalogue: the "
                "same reading of «известные уязвимости» as 117 КУ and 21 АНЗ.1. The "
                "measure is remediation, not the existence of a scan."
            ),
        ),
        Control(
            control_id="ОПО.4",
            title="Установка обновлений программного обеспечения",
            signals=(sig.OVERDUE_REMEDIATION, sig.OVERDUE_FSTEC_WINDOW),
            rationale=(
                "A finding past the subject's own deadline or past the FSTEC window for "
                "its level: an update not installed on either clock."
            ),
        ),
        Control(
            control_id="УКФ.3",
            title="Установка только разрешённого к использованию программного обеспечения",
            signals=(sig.UNASSESSABLE_SOFTWARE,),
            requires=(SOURCE_ENDPOINT_INVENTORY,),
            rationale="Installed software the advisory matcher could not assess.",
        ),
        Control(
            control_id="ИАФ.4",
            title="Управление средствами аутентификации",
            signals=(sig.WEAK_CREDENTIALS,),
            rationale="Default, anonymous or absent authentication observed on a service.",
        ),
        Control(
            control_id="ИАФ.7",
            title="Защита аутентификационной информации при передаче",
            signals=(sig.INSECURE_PROTOCOL,),
            rationale=(
                "Telnet, FTP and unencrypted management carry credentials in cleartext, "
                "which is the transmission the measure protects."
            ),
        ),
        Control(
            control_id="УПД.13",
            title="Реализация защищённого удалённого доступа",
            combinations=(_CLEARTEXT_FROM_UNTRUSTED, _WEAK_AUTH_FROM_UNTRUSTED),
            rationale="Cleartext or weakly authenticated services observed as internet-facing.",
        ),
        Control(
            control_id="ЗИС.2",
            title="Защита периметра информационной (автоматизированной) системы",
            combinations=(_ADMIN_FROM_UNTRUSTED,),
            rationale="Administrative or database services reachable from an untrusted network.",
        ),
        Control(
            control_id="ЗИС.8",
            title="Сокрытие архитектуры и конфигурации системы",
            signals=(sig.INFORMATION_DISCLOSURE,),
            rationale="Web services disclosing version, configuration or diagnostic detail.",
        ),
        Control(
            control_id="ЗИС.19",
            title="Защита информации при её передаче по каналам связи",
            signals=(sig.WEAK_CRYPTOGRAPHY, sig.INSECURE_PROTOCOL),
            rationale="Deprecated TLS, weak ciphers, invalid certificates and cleartext services.",
        ),
    ),
)


_GOST_57580_1 = Framework(
    framework_id="gost-r-57580.1-2017",
    name="ГОСТ Р 57580.1",
    version="2017",
    scope_note=(
        "ГОСТ Р 57580.1-2017 «Защита информации финансовых организаций. Базовый состав "
        "организационных и технических мер», применяемый по положениям Банка России "
        "(683-П, 757-П и др.). В каталоге — технические меры процессов 1–3 (ИУ, СМЭ, ЗВС, "
        "ЦЗИ), для которых есть свидетельства сканирования и инвентаря. Уровень защиты "
        "(1–3), контуры безопасности, организационные меры (О/Н) и оценка соответствия по "
        "ГОСТ Р 57580.2 не представлены."
    ),
    controls=(
        Control(
            control_id="ИУ.1",
            title="Учёт созданных, используемых и (или) эксплуатируемых ресурсов доступа",
            signals=(sig.STALE_ASSET, sig.UNOWNED_ASSET, sig.UNCLASSIFIED_ASSET),
            requires=(SOURCE_ASSETS,),
            rationale=(
                "An asset with no owner, no classification or no recent observation is a "
                "resource the register does not account for."
            ),
        ),
        Control(
            control_id="СМЭ.3",
            title="Межсетевое экранирование сегментов контуров безопасности",
            combinations=(_ADMIN_FROM_UNTRUSTED,),
            rationale="Administrative or database services reachable from an untrusted network.",
        ),
        Control(
            control_id="ЗВС.1",
            title="Защищённые сетевые протоколы при доступе через неконтролируемые каналы",
            signals=(sig.WEAK_CRYPTOGRAPHY, sig.INSECURE_PROTOCOL),
            rationale="Deprecated TLS, weak ciphers, invalid certificates and cleartext services.",
        ),
        Control(
            control_id="ЦЗИ.2",
            title="Устранение уязвимостей, допускающих взаимодействие внутренних сетей с Интернетом",
            combinations=((sig.UNPATCHED_CVE, sig.INTERNET_EXPOSED),),
            severity_floor="high",
            rationale=(
                "Open critical and high CVEs on services observed as internet-facing. The "
                "conjunction is the measure's own wording: an internal CVE is not evidence "
                "about the Internet boundary."
            ),
        ),
        Control(
            control_id="ЦЗИ.4",
            title="Устранение уязвимостей, допускающих несанкционированный логический доступ",
            signals=(sig.WEAK_CREDENTIALS, sig.KNOWN_EXPLOITED),
            rationale=(
                "Default or absent authentication, and vulnerabilities known to be exploited "
                "for access, still open on the estate."
            ),
        ),
        Control(
            control_id="ЦЗИ.5",
            title="Устранение уязвимостей, допускающих несанкционированный удалённый доступ",
            combinations=(_CLEARTEXT_FROM_UNTRUSTED, _WEAK_AUTH_FROM_UNTRUSTED),
            rationale="Cleartext or weakly authenticated services observed as internet-facing.",
        ),
        Control(
            control_id="ЦЗИ.6",
            title="Устранение уязвимостей, допускающих доступ к ресурсам внутренних сетей",
            signals=(sig.UNPATCHED_CVE, sig.KNOWN_EXPLOITED),
            severity_floor="high",
            rationale=(
                "Open critical and high CVEs and anything on the CISA KEV catalogue, "
                "wherever on the estate they are reachable from."
            ),
        ),
        Control(
            control_id="ЦЗИ.7",
            title="Сканирование и анализ параметров настроек серверного и сетевого оборудования",
            signals=(sig.MISCONFIGURATION, sig.INFORMATION_DISCLOSURE),
            rationale="Insecure configuration and disclosure observed on live services.",
        ),
        Control(
            control_id="ЦЗИ.8",
            title="Оперативное устранение уязвимостей ПО серверного и сетевого оборудования",
            signals=(sig.OVERDUE_REMEDIATION, sig.OVERDUE_FSTEC_WINDOW),
            rationale=(
                "A finding past the organisation's own deadline or past the FSTEC window for "
                "its level. «Оперативное» is measured on both clocks; either one missed fails "
                "the measure."
            ),
        ),
        Control(
            control_id="ЦЗИ.9",
            title="Сканирование состава и версий ПО на АРМ пользователей и персонала",
            signals=(sig.UNASSESSABLE_SOFTWARE,),
            requires=(SOURCE_ENDPOINT_INVENTORY,),
            rationale=(
                "Installed packages the advisory matcher could not resolve are workstation "
                "software whose versions cannot be checked for known vulnerabilities."
            ),
        ),
    ),
)


FRAMEWORKS: dict[str, Framework] = {
    framework.framework_id: framework
    for framework in (
        _PCI_DSS_4_0,
        _CIS_V8,
        _ISO_27001_2022,
        _FSTEC_117,
        _FSTEC_21,
        _FSTEC_239,
        _GOST_57580_1,
    )
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
