import datetime
import uuid
from typing import List, Dict, Tuple
from urllib import parse

from eiq_edk import create_entity
from eiq_edk.schemas._validation import valid_domain

intel_requirements_map = {
    "1.1.1": "Ransomware malware",
    "1.1.2": "Mobile malware",
    "1.1.3": "Remote Access Trojan (RAT) malware",
    "1.1.4": "Banking trojan malware",
    "1.1.5": "Information stealer malware",
    "1.1.6": "Loader malware",
    "1.1.7": "Botnet malware",
    "1.1.8": "Worm malware",
    "1.1.9": "Point-Of-Sale (PoS) malware",
    "1.1.10": "ATM malware",
    "1.1.11": "Internet of Things (IoT) malware",
    "1.1.12": "Denial of Service (DoS) malware",
    "1.1.13": "Proxy malware",
    "1.1.14": "Destructive malware",
    "1.1.15": "Cryptomining malware",
    "1.1.16": "Formgrabber, Web Inject, Automatic Transfer Systems (ATS) malware",
    "1.2.1": "Multifunctional Malware-as-a-Service (MaaS) platforms",
    "1.2.2": "Crypter/FUD services",
    "1.2.3": "Anti/Counter-AV services",
    "1.2.4": "Ransomware-as-a-Service (RaaS)",
    "1.2.5": "Spamming services",
    "1.2.6": "DoS/booter/stresser services",
    "1.2.7": "Rogue Code Signing certificate providers",
    "1.2.8": "Rogue Web certificate providers",
    "1.3.1": "Malware install providers",
    "1.3.2": "Malvertising",
    "2.1.1": "Operating System (OS) vulnerabilities",
    "2.1.1.1": "Desktop/Server OS vulnerabilities",
    "2.1.1.2": "Mobile OS vulnerabilities",
    "2.1.2": "Software and web application vulnerabilities",
    "2.1.2.1": "Web browser vulnerabilities",
    "2.1.2.2": "Office / productivity software vulnerabilitie",
    "2.1.2.3": "Open source software library vulnerabilities",
    "2.1.3": "Protocol vulnerabilities",
    "2.1.4": "Server platform vulnerabilities",
    "2.1.4.1": "Database server vulnerabilities",
    "2.1.4.2": "Web server vulnerabilities",
    "2.1.4.3": "Email server vulnerabilities",
    "2.1.4.4": "Content management server vulnerabilities",
    "2.1.5": "Network appliance / endpoint vulnerabilities",
    "2.1.6": "Cloud computing / storage vulnerabilities",
    "2.1.7": "Hardware vulnerabilities",
    "2.1.8": "Other platform vulnerabilities",
    "2.1.8.1": "Transportation controls vulnerabilities",
    "2.1.8.2": "Industrial controls systems vulnerabilities",
    "2.1.8.3": "IoT-related vulnerabilities",
    "2.1.8.4": "Healthcare systems related vulnerabilities",
    "2.2.1": "Exploit Proof-of-concept (PoC) code",
    "2.2.2": "Exploit kits",
    "3.1.1": "Bulletproof Hosting (BPH) services",
    "3.1.2": "Proxy services",
    "3.1.3": "Domain registrar services",
    "3.1.4": "Botnet services",
    "4.1.1": "Cash-out services",
    "4.1.2": "Money laundering and exchange services",
    "4.1.3": "Money mule accounts and networks",
    "4.1.4": "Bank account drops and fund transfers",
    "4.1.5": "Prepaid cards / gift cards",
    "4.1.6": "Travel fraud",
    "4.1.7": "Hospitality fraud",
    "4.1.8": "Tax fraud",
    "4.1.9": "CEO/CFO fraud / Business Email Compromise (BEC)",
    "4.1.10": "Documentation fraud",
    "4.1.11": "Insurance fraud",
    "4.2.1": "Compromised payment cards (CVVs, fullz, dumps)",
    "4.2.2": "Compromised account credentials",
    "4.2.3": "Compromised Personally Identifiable Information (PII)",
    "4.2.4": "Compromised Intellectual Property (IP)",
    "4.3.1": "Call center services",
    "4.3.2": "Account checking services",
    "4.3.3": "Brute force tools",
    "4.3.3.1": "Credential stuffing",
    "4.4.1": "Phishing",
    "4.4.2": "Spearphishing",
    "4.4.3": "Vishing",
    "4.4.4": "Social media scams",
    "4.4.5": "Smishing",
    "5.1.1": "Reconaissance & information gathering (Att&ck)",
    "5.1.2": "Weaponization (Att&ck)",
    "5.1.3": "Delivery (Att&ck)",
    "5.2.1": "Initial Access (Att&ck)",
    "5.2.2": "Execution (Att&ck)",
    "5.2.3": "Persistence (Att&ck)",
    "5.2.4": "Privilege Escalation (Att&ck)",
    "5.2.5": "Defense Evasion (Att&ck)",
    "5.2.6": "Credential Access (Att&ck)",
    "5.2.7": "Discovery (Att&ck)",
    "5.2.8": "Lateral Movement (Att&ck)",
    "5.2.9": "Collection (Att&ck)",
    "5.2.10": "Exfiltration (Att&ck)",
    "5.2.11": "Command and Control (Att&ck)",
    "5.3.1": "Denial of Service (DoS) attacks",
    "5.3.2": "Injection attacks",
    "5.3.3": "Website defacements",
    "5.3.4": "Brute Force Attacks",
    "5.4.1": "ATM attacks: skimming, shimming, jackpotting",
    "5.4.2": "PoS attacks: skimming",
    "5.4.3": "Physical sabotage of network / system",
    "5.5": "Insider threats",
    "5.6.1": "Espionage",
    "5.6.2": "Outsider trading",
    "5.6.3": "Information or data breach",
    "6.1.1": "Consumer & Industrial Products",
    "6.1.1.1": "Consumer Business",
    "6.1.1.2": "Aviation & Transportation",
    "6.1.1.3": "Consumer Products",
    "6.1.1.4": "Sports & Leisure",
    "6.1.1.5": "Hospitality",
    "6.1.1.6": "Restaurants & Food Service",
    "6.1.1.7": "Retail, Wholesale & Distribution",
    "6.1.2": "Energy & Resources",
    "6.1.2.1": "Oil. Gas, and Consumable Fuels",
    "6.1.2.2": "Power & Utilities",
    "6.1.2.3": "Shipping & Ports",
    "6.1.2.4": "Water",
    "6.1.3": "Financial Services",
    "6.1.3.1": "Banking & Securities",
    "6.1.3.2": "Insurance",
    "6.1.3.3": "Investment Management",
    "6.1.4": "Life Sciences & Health Care",
    "6.1.4.1": "Health Care Providers and Services",
    "6.1.4.2": "Health Care Equipment and Technology",
    "6.1.4.3": "Pharmaceuticals, Biotechnology and Life Sciences",
    "6.1.5": "Manufacturing",
    "6.1.5.1": "Aerospace & Defense",
    "6.1.5.2": "Automotive",
    "6.1.5.3": "Industrial Products & Services",
    "6.1.5.4": "Chemicals & Specialty Materials",
    "6.1.6": "Public Sector",
    "6.1.6.1": "International Government",
    "6.1.6.2": "National Government",
    "6.1.6.3": "Regional Government",
    "6.1.6.4": "Education",
    "6.1.6.5": "Public Safety",
    "6.1.6.6": "Military and Defense",
    "6.1.7": "Real Estate",
    "6.1.7.1": "Engineering and Construction Industry",
    "6.1.7.2": "Real Estate Fund and Investor",
    "6.1.7.3": "REIT and Property Company",
    "6.1.7.4": "Real Estate Management, Brokerage, and Service Provider",
    "6.1.7.5": "Tenants and Occupiers",
    "6.1.8": "Technology, Media & Telecommunications",
    "6.1.8.1": "Technology",
    "6.1.8.2": "Media & Entertainment",
    "6.1.8.3": "Communications",
    "6.1.8.4": "Internet of Things",
    "6.1.9": "Professional Services & Consulting",
    "6.1.9.1": "IT/Technology Consulting",
    "6.1.9.2": "Management & Operations Consulting",
    "6.1.9.3": "Financial & Investment Consulting",
    "6.1.9.4": "Human Resources Consulting",
    "6.1.9.5": "Marketing & Sales Consulting",
    "6.1.9.6": "Law Services & Consulting",
    "6.1.9.7": "Political Consulting",
    "6.1.9.8": "Physical Security Consulting",
    "6.2.1": "Africa",
    "6.2.2": "Asia",
    "6.2.3": "Central America",
    "6.2.4": "Europe",
    "6.2.5": "European Union",
    "6.2.6": "Middle East",
    "6.2.7": "North America",
    "6.2.8": "Oceania",
    "6.2.9": "South America",
    "6.2.10": "The Caribbean",
}

INDICATOR_TYPE = {
    "file": "File Hash Watchlist",
    "ipv4": "IP Watchlist",
    "url": "URL Watchlist",
    "domain": "Domain Watchlist",
}

EXTRACTS_MAPPING = {
    "md5": "hash-md5",
    "sha1": "hash-sha1",
    "sha256": "hash-sha256",
    "ssdeep": "hash-ssdeep",
    "url": "uri",
    "ipv4": "ipv4",
    "domain": "domain",
    "port": "port",
}

SUPPORTED_OBSERVABLE_TYPES = [
    "hash-md5",
    "hash-sha1",
    "hash-sha256",
    "hash-ssdeep",
    "uri",
    "ipv4",
    "domain",
]


def parse_indicators(
    data: list, entities: list, relations: list, feed_type: str = None
):
    for raw_value in data:
        indicator_yara_data = raw_value["data"]
        entity_data, entity_meta = {"type": "indicator"}, {}
        entity_meta["tags"] = [
            indicator_yara_data["threat"]["type"],
            indicator_yara_data["threat"]["data"]["family"],
        ]
        types, test_mechanisms, references = [], [], []
        estimated_threat_start_time, estimated_threat_end_time, description = "", "", ""
        confidence = indicator_yara_data["confidence"]
        estimated_threat_start_time = datetime.datetime.utcfromtimestamp(
            raw_value["activity"]["first"] / 1000
        ).isoformat()
        if indicator_yara_data.get("intel_requirements"):
            entity_meta["tags"].extend(
                create_intel_requirements_tags(
                    indicator_yara_data["intel_requirements"]
                )
            )
        if feed_type == "YARA":
            title = f'YARA Rule: {indicator_yara_data["yara_data"]["title"]}'
            uuid_id = "{{http://www.intel471.com/}}indicator-{}".format(
                str(
                    uuid.uuid5(
                        uuid.NAMESPACE_X500, indicator_yara_data["yara_data"]["title"]
                    )
                )
            )
            references = [
                f'https://api.intel471.com/v1/yara?threatuid={raw_value.get("uid")}'
            ]
            types.append({"value": "Malware Artifacts"})
            test_mechanisms.append({
                "type": "yara",
                "value": indicator_yara_data["yara_data"]["signature"],
                "producer": {
                    "identity": "Intel471 Malware Intelligence Reports",
                    "references": references,
                    "time_start": datetime.datetime.utcfromtimestamp(
                        raw_value["activity"]["first"] / 1000
                    ).isoformat(),
                }
            })
        else:
            title = create_indicator_title(raw_value)
            uuid_id = "{{http://www.intel471.com/}}indicator-{}".format(
                str(uuid.uuid5(uuid.NAMESPACE_X500, title))
            )
            entity_meta["extracts"] = make_extracts(
                indicator_yara_data["indicator_type"],
                indicator_yara_data["indicator_data"],
                confidence,
            )
            entity_data["description"] = create_description(indicator_yara_data)
            types = create_indicator_types(
                indicator_yara_data["indicator_type"],
                indicator_yara_data["mitre_tactics"],
            )
            estimated_threat_end_time = datetime.datetime.utcfromtimestamp(
                indicator_yara_data["expiration"] / 1000
            ).isoformat()
            references = [
                f"https://api.intel471.com/v1/indicators?"
                f'indicator={raw_value.get("uid")}'
            ]
            if indicator_yara_data["indicator_type"] == "file":
                references.append(
                    indicator_yara_data["indicator_data"]["file"]["download_url"]
                )
        producer = {
            "identity": "Intel471 Malware Intelligence Reports",
            "references": references,
            "description": "https://www.intel471.com/",
            "roles": ["Initial Author"],
        }
        entity_data.update({
            "title": title,
            "id": uuid_id,
            "types": types,
            "confidence": confidence.capitalize(),
            "producer": producer,
            "test_mechanisms": test_mechanisms
        })
        entity_meta.update({
            "estimated_threat_start_time": estimated_threat_start_time,
            "estimated_threat_end_time": estimated_threat_end_time
        })
        indicator = create_entity({"type": "indicator", "data": entity_data, "meta": entity_meta})
        entities.append(indicator)
        parse_ttps(data, entities, relations, "Malware Variant")


def parse_ttps(
    data: list,
    entities: list,
    relations: list,
    malware_type: str = None,
    feed_type: str = None,
    raw_report: list = None,
):
    ttps, ttps_relations, references = [], [], []
    estimated_threat_end_time, estimated_observed_time = "", ""
    for index, raw_value in enumerate(data):
        entity_data, entity_meta = {"type": "ttp"}, {}
        tags = []
        threat_data = raw_value["data"]["threat"]["data"]
        if raw_value["data"].get("intel_requirements"):
            tags = create_intel_requirements_tags(
                raw_value["data"]["intel_requirements"]
            )
        tags.append(raw_value["data"]["threat"]["type"])
        if malware_type == "Malware Variant":
            ttp_uuid = str(uuid.uuid5(uuid.NAMESPACE_X500, raw_value["uid"]))
            title = f'Malware Variant: {threat_data["family"]} {ttp_uuid[-6:]}'
            if raw_value["data"].get("expiration"):
                entity_meta["estimated_threat_end_time"] = datetime.datetime.utcfromtimestamp(
                    raw_value["data"]["expiration"] / 1000
                ).isoformat()
            entity_meta["estimated_threat_start_time"] = datetime.datetime.utcfromtimestamp(
                raw_value["activity"]["first"] / 1000
            ).isoformat()
            entity_meta["estimated_observed_time"] = datetime.datetime.utcfromtimestamp(
                raw_value["activity"]["first"] / 1000
            ).isoformat()
            if feed_type == "YARA":
                references = [
                    f'https://api.intel471.com/v1/yaraw_reportra?threatuid={raw_value.get("uid")}'
                ]
            else:
                references = [
                    f"https://api.intel471.com/v1/indicators?"
                    f'indicator={raw_value.get("uid")}'
                ]
            ttp_relation = {
                "data": {
                    "source": len(entities) - 1,
                    "target": len(entities),
                    "target_type": "ttp",
                    "source_type": "indicator",
                    "key": "indicated_ttps",
                    "type": "relation",
                }
            }
        else:
            title = f'Malware: {threat_data["family"]}'
            ttp_uuid = str(uuid.uuid5(uuid.NAMESPACE_X500, threat_data["family"]))
            tags.append(threat_data["family"])
            if raw_value["data"].get("malware_report_data"):
                release_at = raw_value["data"]["malware_report_data"]["released_at"]
                entity_meta["estimated_observed_time"] = datetime.datetime.utcfromtimestamp(
                    release_at / 1000
                ).isoformat()
            entity_meta["estimated_threat_start_time"] = datetime.datetime.utcfromtimestamp(
                raw_value["activity"]["first"] / 1000
            ).isoformat()
            if raw_report:
                references = [
                    f"https://api.intel471.com/v1/malwareReports?"
                    f'malwareFamilyProfileUid={raw_report[0].get("uid")}'
                ]
            ttp_relation = {
                "data": {
                    "source": len(entities) - 1,
                    "target": len(entities),
                    "target_type": "ttp",
                    "source_type": "ttp",
                    "key": "related_ttps",
                    "type": "relation",
                }
            }
        behavior = {
            "malware": [
                {
                    "names": [{"value": threat_data["family"]}],
                    "type": "malware-instance",
                }
            ],
            "type": "behavior",
        }
        producer = {
            "identity": "Intel471 Malware Intelligence Reports",
            "references": references,
            "description": "https://www.intel471.com/",
            "roles": ["Initial Author"],
        }
        uuid_id = "{{http://www.intel471.com/}}ttp-{}".format(ttp_uuid)
        entity_data.update({
            "title": title,
            "id": uuid_id,
            "producer": producer,
            "behaviour": behavior
        })
        entity_meta.update({
            "tags": tags,
        })
        ttp = create_entity({"type": "ttp","data": entity_data, "meta": entity_meta})
        ttps.append(ttp)
        ttps_relations.append(ttp_relation)
    entities.extend(ttps)
    relations.extend(ttps_relations)


def parse_report(data: list, entities: list) -> Tuple[List, List]:
    reports, reports_relations = [], []
    for raw_report in data:
        entity_data, entity_meta = {"type": "report"}, {}
        report_data = raw_report["data"]
        entity_meta["estimated_observed_time"] = datetime.datetime.utcfromtimestamp(
            report_data["malware_report_data"].get("released_at") / 1000
        ).isoformat()
        entity_meta["estimated_threat_start_time"] = datetime.datetime.utcfromtimestamp(
            raw_report["activity"]["first"] / 1000
        ).isoformat()
        references = [
            (
                f"https://api.intel471.com/v1/malwareReports?"
                f'malwareFamilyProfileUid={raw_report.get("uid")}'
            )
        ]
        report_title = report_data["malware_report_data"].get("title")
        report_id = str(uuid.uuid5(uuid.NAMESPACE_X500, report_data["threat"]["uid"]))
        tags = [
            report_data["threat"].get("type"),
            report_data["threat"]["data"].get("family"),
        ]
        producer = {
            "identity": "Intel471 Malware Intelligence Reports",
            "references": references,
            "description": "https://www.intel471.com/",
            "roles": ["Initial Author"],
        }
        _id = "{{https://www.intel471.com/}}report-{}".format(report_id)
        entity_data.update({
            "title": f"Intel471 - {report_title}",
            "id": _id,
            "description": report_data["malware_report_data"].get("text"),
            "producer": producer,
            "intents": [{"value":"Malware Characterization"}]
        })
        entity_meta.update({
            "tags": tags,
        })
        report = create_entity({"type": "report","data": entity_data, "meta": entity_data})

        report_relation = {
            "data": {
                "source": len(entities),
                "target": len(entities) - 1,
                "target_type": "report",
                "source_type": "ttp",
                "key": "ttps",
                "type": "relation",
            }
        }
        reports.append(report)
        reports_relations.append(report_relation)
    return reports, reports_relations


def create_intel_requirements_tags(requirements: list) -> List:
    tags = []
    for requirement in requirements:
        if requirement in intel_requirements_map:
            tags.append(
                f"Intelligence Requirement - " f"{intel_requirements_map[requirement]}"
            )
    return tags

def make_extracts(indicator_type: str, indicator_data: dict, confidence: str) -> List:
    extracts = []
    if indicator_type == "file":
        for file_type in indicator_data["file"]:
            if file_type in EXTRACTS_MAPPING:
                extracts.append(
                    create_extract(
                        EXTRACTS_MAPPING[file_type],
                        indicator_data["file"][file_type],
                        maliciousness=confidence,
                    )
                )
    elif indicator_type == "url":
        process_url_extracts(indicator_data, extracts, confidence)

    elif indicator_type == "ipv4":
        process_ipv4_extracts(indicator_data, indicator_type, extracts, confidence)
    extracts = filter_empty_extracts(extracts)
    return extracts

def create_extract(
    kind: str,
    value: str,
    maliciousness: str = None,
    link_type: str = None,
) -> dict:
    extract = {
        "kind": kind,
        "value": value,
        "meta": {}
    }
    if link_type:
        extract['link_type'] = link_type
    if maliciousness:
        extract['meta']['maliciousness'] = maliciousness
    return extract

def process_ipv4_extracts(indicator_data, indicator_type, extracts, confidence):
    extracts.append(
        create_extract(
            EXTRACTS_MAPPING[indicator_type],
            indicator_data["address"],
            maliciousness=confidence,
        )
    )
    if indicator_data.get("geo_ip"):
        geo_ip = indicator_data["geo_ip"]
        append_if_exist(extracts, "country", geo_ip, "country", confidence=confidence)
        append_if_exist(
            extracts, "country_code", geo_ip, "country-code", confidence=confidence
        )
        append_if_exist(
            extracts, "city", geo_ip, "city", confidence=confidence
        )
        if geo_ip.get("isp"):
            isp = geo_ip["isp"]
            append_if_exist(
                extracts, "network", isp, "ipv4", confidence=confidence
            )
            append_if_exist(
                extracts, "autonomous_system", isp, "asn", confidence=confidence,
            )
            append_if_exist(
                extracts, "isp", isp, "registrar", confidence=confidence
            )
            append_if_exist(
                extracts, "organization", isp, "organization", confidence=confidence,
            )



def process_url_extracts(indicator_data, extracts, confidence):
    parsed_url = parse.urlparse(indicator_data["url"])
    extract_value = indicator_data.get("url")
    if parsed_url.port:
        extract_value = f'{indicator_data.get("url")}/'
        extracts.append(
            create_extract(
                EXTRACTS_MAPPING["port"],
                str(parsed_url.port),
            )
        )
        extracts.append(
            create_extract(
                EXTRACTS_MAPPING["domain"]
                if valid_domain(parsed_url.hostname)  # Take validation from dev_kit
                else EXTRACTS_MAPPING["ipv4"],
                parsed_url.hostname,
                maliciousness=confidence,
            )
        )
    extracts.append(
        create_extract(
            EXTRACTS_MAPPING["url"],
            extract_value,
            maliciousness=confidence,
        )
    )


def append_if_exist(
    extracts: List[Dict],
    _key: str,
    _dict: dict,
    kind: str,
    confidence: str = None,
):
    if _dict.get(_key):
        extract = create_extract(
            kind,
            _dict[_key],
            maliciousness=confidence,
        )
        if extract:
            extracts.append(extract)

def filter_empty_extracts(extracts):
    extracts = [i for i in extracts if i]
    return extracts

def create_indicator_title(data: dict) -> str:
    indicator_data = data["data"]
    title = ""
    if indicator_data["indicator_type"] == "file":
        title = (
            indicator_data["indicator_data"]
            .get("file")
            .get(list(indicator_data["indicator_data"].get("file").keys())[0])
        )
    elif indicator_data["indicator_type"] == "ipv4":
        title = indicator_data["indicator_data"].get("address")
    elif indicator_data["indicator_type"] == "url":
        parsed_url = parse.urlparse(indicator_data["indicator_data"].get("url"))
        if parsed_url.port:
            title = f'{indicator_data["indicator_data"].get("url")}/'
        else:
            title = indicator_data["indicator_data"].get("url")

    return title


def create_description(data: dict) -> str:
    description = f'<p>{data["context"].get("description", "")}</p>'
    if data["indicator_type"] == "file" and data["indicator_data"]["file"].get("type"):
        file_type = data["indicator_data"]["file"]["type"]
        description += f"<p><strong>Type:</strong> {file_type}</p>"
    return description


def create_indicator_types(indicator_type: str, mitre_tactics: str) -> List:
    types = []
    for type_value in INDICATOR_TYPE:
        if type_value == indicator_type:
            types.append({"value": INDICATOR_TYPE[indicator_type]})
    if mitre_tactics == "command_and_control" and indicator_type != "file":
        types.append({"value":"C2"})

    return types
