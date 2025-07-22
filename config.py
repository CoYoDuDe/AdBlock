import os
import re

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
TMP_DIR = os.path.join(SCRIPT_DIR, "tmp")
DB_PATH = os.path.join(TMP_DIR, "adblock_cache.db")
HOSTS_HASH_PATH = os.path.join(TMP_DIR, "hosts_hash.txt")
TRIE_CACHE_PATH = os.path.join(TMP_DIR, "trie_cache.pkl")
REACHABLE_FILE = os.path.join(TMP_DIR, "reachable.txt")
UNREACHABLE_FILE = os.path.join(TMP_DIR, "unreachable.txt")

MAX_DNS_CACHE_SIZE = 10000

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

DOMAIN_PATTERN = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1|[0-9a-fA-F:]+)\s+(\S+)|^\s*(\S+)|^\|\|([^\^]+)\^$")
DOMAIN_VALIDATOR = re.compile(
    r"^(?!-|\.)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)

DEFAULT_CONFIG = {
    "log_file": "./logs/adblock.log",
    "log_format": "text",
    "max_retries": 3,
    "retry_delay": 2,
    "dns_retry_strategy": "exponential",
    "dns_config_file": "dnsmasq.conf",
    "hosts_file": "hosts.txt",
    "hosts_ip": "0.0.0.0",
    "web_server_ipv4": "127.0.0.1",
    "web_server_ipv6": "::1",
    "use_ipv4_output": True,
    "use_ipv6_output": False,
    "github_upload": False,
    "github_repo": "git@github.com:example/repo.git",
    "github_branch": "main",
    "git_user": "",
    "git_email": "",
    "dns_servers": [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
    ],
    "logging_level": "INFO",
    "detailed_log": False,
    "save_unreachable": True,
    "prioritize_lists": True,
    "domain_timeout": 3,
    "domain_cache_validity_days": 7,
    "cache_flush_interval": 300,
    "cache_trie": True,
    "always_check_all_domains": False,
    "priority_lists": [],
    "send_email": False,
    "use_smtp": True,
    "email_recipient": "example@example.com",
    "email_sender": "no-reply@example.com",
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "remove_redundant_subdomains": True,
    "export_prometheus": False,
    "category_weights": {"malware": 1.5, "adult": 1.2, "ads": 1.0, "unknown": 0.8},
    "use_bloom_filter": True,
    "bloom_filter_capacity": 10000000,
    "bloom_filter_error_rate": 0.001,
    "http_timeout": 60,
    "resource_thresholds": {
        "low_memory_mb": 150,
        "emergency_memory_mb": 50,
        "high_cpu_percent": 90,
        "high_latency_s": 5.0,
        "moving_average_window": 5,
        "consecutive_violations": 2,
    },
}
