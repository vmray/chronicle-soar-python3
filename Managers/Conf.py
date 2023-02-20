INTEGRATION_NAME = "VMRayCustomIntegration"
INTEGRATION_DISPLAY_NAME = "VMRayCustomIntegration"


# Actions
PING_SCRIPT_NAME = "%s - Ping" % INTEGRATION_DISPLAY_NAME
SUBMIT_SAMPLE_SCRIPT_NAME = "%s - Submit Sample" % INTEGRATION_DISPLAY_NAME
SUBMIT_URL_SCRIPT_NAME = "%s - Submit Url" % INTEGRATION_DISPLAY_NAME
SUBMIT_HASH_SCRIPT_NAME = "%s - Submit Hash" % INTEGRATION_DISPLAY_NAME
GET_SUBMISSION_RESULT_SCRIPT_NAME = "%s - Get Submission Result" % INTEGRATION_DISPLAY_NAME
GET_SAMPLE_IOC_SCRIPT_NAME = "%s - Get Sample IOCs" % INTEGRATION_DISPLAY_NAME
GET_SAMPLE_VTI_SCRIPT_NAME = "%s - Get Sample VTIs" % INTEGRATION_DISPLAY_NAME
GET_SAMPLE_ATTACK_SCRIPT_NAME = "%s - Get Sample MITRE ATT&CK Techniques"  % INTEGRATION_DISPLAY_NAME
GET_SAMPLE_REPORT_SCRIPT_NAME = "%s - Get Sample Report" % INTEGRATION_DISPLAY_NAME
GET_SAMPLE_REPORT_SCRIPT_NAME_1 = "%s - Get Sample Report_1" % INTEGRATION_DISPLAY_NAME
GET_ANALYSIS_ARCHIVE_SCRIPT_NAME = "%s - Get Analysis Archive" % INTEGRATION_DISPLAY_NAME
UNLOCK_REPORT_SCRIPT_NAME = "%s - Unlock Report" % INTEGRATION_DISPLAY_NAME
GET_CHILD_SAMPLES_SCRIPT_NAME = "%s - Get Child Samples" % INTEGRATION_DISPLAY_NAME


# VMRay verdicts enum
class VERDICT:
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CLEAN = "clean"


# VMRay analyzer modes
class ANALYZER_MODE:
    REPUTATION = "reputation"
    REPUTATION_STATIC = "reputation_static"
    REPUTATION_STATIC_DYNAMIC = "reputation_static_dynamic"
    STATIC_DYNAMIC = "static_dynamic"
    STATIC = "static"


# VMRay related hash types
class HASH:
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


# VMRay IOC types
class IOC_TYPES:
    DOMAINS = "domains"
    EMAILS = "emails"
    EMAIL_ADDRESSES = "email_addresses"
    FILES = "files"
    FILENAMES = "filenames"
    IPS = "ips"
    MUTEXES = "mutexes"
    PROCESSES = "processes"
    REGISTRY = "registry"
    URLS = "urls"


# VMRay IOC and field mappings to extract necessary fields
IOC_KEY_MAPPINGS = {
    IOC_TYPES.FILES: [
        "categories",
        "classifications",
        "filenames",
        "hashes",
        "parent_files",
        "parent_processes",
        "parent_processes_names"
        "threat_names",
        "verdict",
        "operations",
    ],
    IOC_TYPES.FILENAMES: [
        "categories",
        "classifications",
        "filename",
        "verdict",
        "operations",
        "threat_names"
    ],
    IOC_TYPES.PROCESSES: [
        "classifications",
        "verdict",
        "cmd_line",
        "image_names",
        "parent_processes",
        "parent_processes_names",
        "process_names",
        "threat_names"
    ],
    IOC_TYPES.REGISTRY: [
        "classifications",
        "verdict",
        "operations",
        "parent_processes",
        "parent_processes_names",
        "reg_key_name",
        "threat_names"
    ],
    IOC_TYPES.URLS: [
        "classifications",
        "categories",
        "countries",
        "country_codes",
        "ip_addresses",
        "original_urls",
        "parent_files",
        "parent_processes",
        "parent_processes_names",
        "referrers",
        "url",
        "user_agents",
        "verdict"
    ],
    IOC_TYPES.DOMAINS: [
        "classifications",
        "countries",
        "country_codes",
        "verdict",
        "domain",
        "ip_addresses",
        "original_domains",
        "parent_processes",
        "parent_processes_names",
        "protocols"
    ],
    IOC_TYPES.IPS: [
        "classifications",
        "country",
        "country_code",
        "domains",
        "ip_address",
        "parent_processes",
        "parent_processes_names",
        "protocols",
        "verdict"
    ],
    IOC_TYPES.MUTEXES: [
        "classifications",
        "verdict",
        "mutex_name",
        "operations",
        "parent_processes",
        "parent_processes_names",
        "threat_names"
    ]
}


# VMRay VTI field mappings to extract necessary fields
VTI_KEY_MAPPINGS = [
    "classifications",
    "operation",
    "score"
]


# VMRay MITRE ATTACK field mappings to extract necessary fields
MITRE_ATTACK_KEY_MAPPINGS = [
    "tactics",
    "technique",
    "technique_id"
]

# VMRay submission field mappings to extract necessary fields
SUBMISSION_KEY_MAPPINGS = [
    "submission_created",
    "submission_finished",
    "submission_id",
    "submission_original_url",
    "submission_original_filename",
    "submission_sample_sha256",
    "submission_score",
    "submission_severity",
    "submission_verdict",
    "submission_webif_url"
]

# VMRay Configuration
class VMRayConfig:
    
    # VMRay Report or Verdict API KEY
    API_KEY = None
    
    # VMRay REST API URL
    URL = None

    # User Agent string for VMRay Api requests
    USER_AGENT = "VMRayAnalyzer/SiemplifyConnector-1.0"

    # SSL Verification setting for self-signed certificates
    SSL_VERIFY = True

    # VMRay Submission Comment
    SUBMISSION_COMMENT = "Sample from Siemplify Connector"

    # VMRay submission tags (Can't contain space)
    SUBMISSION_TAGS = ["Siemplify"]

    # VMRay analysis timeout value (seconds)
    ANALYSIS_TIMEOUT = 120

    # Analyzer mode for normal samples
    ANALYZER_MODE = ANALYZER_MODE.REPUTATION_STATIC_DYNAMIC
    
    # Selected verdicts for processing samples and IOCs
    SELECTED_VERDICTS = [VERDICT.MALICIOUS, VERDICT.SUSPICIOUS]
    
    # Selected IOC verdicts
    SELECTED_IOC_VERDICTS = [VERDICT.MALICIOUS, VERDICT.SUSPICIOUS]
    
    # Selected IOC types
    SELECTED_IOC_TYPES = [IOC_TYPES.DOMAINS, IOC_TYPES.FILES, IOC_TYPES.FILENAMES, IOC_TYPES.IPS, IOC_TYPES.MUTEXES, IOC_TYPES.PROCESSES, IOC_TYPES.REGISTRY, IOC_TYPES.URLS]
    
    # Minimum VTI score for filtering
    MIN_VTI_SCORE = 3

    # Download path for analysis archives
    ANALYSIS_ARCHIVE_DOWNLOAD_URL = "/user/analysis/download?id=%s"
