"""All exposure check definitions with severity and validation logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"


@dataclass
class ExposureCheck:
    """Defines a single exposure check."""

    name: str
    path: str
    severity: str
    description: str
    # HTTP methods to try
    methods: list[str] = field(default_factory=lambda: ["GET"])
    # Validate response — if None, any 2xx is a hit
    # If set, response body must contain this string
    body_contains: Optional[str] = None
    # Response body must NOT contain this (to filter false positives)
    body_not_contains: Optional[str] = None
    # Minimum response size to consider valid
    min_size: int = 10
    # Status codes that indicate a finding (default: 200)
    valid_status_codes: list[int] = field(default_factory=lambda: [200])
    # Extra headers to send
    extra_headers: dict = field(default_factory=dict)


# ============================================================
# EXPOSURE CHECKS — organized by severity
# ============================================================

ALL_CHECKS: list[ExposureCheck] = [

    # ---- CRITICAL: Source Code & Credentials ----
    ExposureCheck("git_head", "/.git/HEAD", SEVERITY_CRITICAL,
                  "Git repository HEAD file exposed — full source code accessible",
                  body_contains="ref:", valid_status_codes=[200]),

    ExposureCheck("git_config", "/.git/config", SEVERITY_CRITICAL,
                  "Git config exposed — may contain credentials and internal URLs",
                  body_contains="[core]", valid_status_codes=[200]),

    ExposureCheck("git_index", "/.git/index", SEVERITY_CRITICAL,
                  "Git index file exposed",
                  min_size=10, valid_status_codes=[200]),

    ExposureCheck("git_packed_refs", "/.git/packed-refs", SEVERITY_CRITICAL,
                  "Git packed refs exposed",
                  body_contains="#", valid_status_codes=[200]),

    ExposureCheck("env_file", "/.env", SEVERITY_CRITICAL,
                  ".env file exposed — likely contains database passwords and API keys",
                  valid_status_codes=[200], min_size=5),

    ExposureCheck("env_backup", "/.env.backup", SEVERITY_CRITICAL,
                  ".env backup file exposed",
                  valid_status_codes=[200], min_size=5),

    ExposureCheck("env_production", "/.env.production", SEVERITY_CRITICAL,
                  ".env.production exposed",
                  valid_status_codes=[200], min_size=5),

    ExposureCheck("env_local", "/.env.local", SEVERITY_CRITICAL,
                  ".env.local exposed",
                  valid_status_codes=[200], min_size=5),

    ExposureCheck("env_dev", "/.env.development", SEVERITY_CRITICAL,
                  ".env.development exposed",
                  valid_status_codes=[200], min_size=5),

    ExposureCheck("env_old", "/.env.old", SEVERITY_CRITICAL,
                  ".env.old exposed",
                  valid_status_codes=[200], min_size=5),

    ExposureCheck("wp_config", "/wp-config.php", SEVERITY_CRITICAL,
                  "WordPress config exposed — contains DB credentials",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("wp_config_bak", "/wp-config.php.bak", SEVERITY_CRITICAL,
                  "WordPress config backup exposed",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("wp_config_old", "/wp-config.php.old", SEVERITY_CRITICAL,
                  "Old WordPress config exposed",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("wp_config_tilde", "/wp-config.php~", SEVERITY_CRITICAL,
                  "Vim backup of WordPress config exposed",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("aws_credentials", "/.aws/credentials", SEVERITY_CRITICAL,
                  "AWS credentials file exposed",
                  body_contains="[", valid_status_codes=[200]),

    ExposureCheck("aws_config", "/.aws/config", SEVERITY_CRITICAL,
                  "AWS config file exposed",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("gcp_credentials", "/credentials.json", SEVERITY_CRITICAL,
                  "GCP credentials JSON exposed",
                  body_contains="client_email", valid_status_codes=[200]),

    ExposureCheck("gcp_service_account", "/service_account.json", SEVERITY_CRITICAL,
                  "GCP service account key exposed",
                  body_contains="private_key", valid_status_codes=[200]),

    ExposureCheck("ssh_rsa", "/id_rsa", SEVERITY_CRITICAL,
                  "Private SSH key (RSA) exposed",
                  body_contains="PRIVATE KEY", valid_status_codes=[200]),

    ExposureCheck("ssh_ed25519", "/id_ed25519", SEVERITY_CRITICAL,
                  "Private SSH key (Ed25519) exposed",
                  body_contains="PRIVATE KEY", valid_status_codes=[200]),

    ExposureCheck("ssh_dir_rsa", "/.ssh/id_rsa", SEVERITY_CRITICAL,
                  "Private SSH key in .ssh directory exposed",
                  body_contains="PRIVATE KEY", valid_status_codes=[200]),

    ExposureCheck("backup_sql", "/backup.sql", SEVERITY_CRITICAL,
                  "SQL database backup exposed",
                  body_contains="INSERT INTO", valid_status_codes=[200]),

    ExposureCheck("dump_sql", "/dump.sql", SEVERITY_CRITICAL,
                  "SQL database dump exposed",
                  body_contains="INSERT INTO", valid_status_codes=[200]),

    ExposureCheck("db_sql", "/database.sql", SEVERITY_CRITICAL,
                  "Database SQL file exposed",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("sqlite_db", "/database.sqlite", SEVERITY_CRITICAL,
                  "SQLite database file exposed",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("django_sqlite", "/db.sqlite3", SEVERITY_CRITICAL,
                  "Django SQLite database exposed",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("backup_zip", "/backup.zip", SEVERITY_CRITICAL,
                  "Backup ZIP archive exposed",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("backup_tar", "/backup.tar.gz", SEVERITY_CRITICAL,
                  "Backup archive exposed",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("rails_db_config", "/config/database.yml", SEVERITY_CRITICAL,
                  "Rails database config exposed — contains DB credentials",
                  body_contains="password", valid_status_codes=[200]),

    ExposureCheck("laravel_log", "/storage/logs/laravel.log", SEVERITY_CRITICAL,
                  "Laravel debug log exposed — may contain session tokens",
                  body_contains="[", valid_status_codes=[200]),

    ExposureCheck("django_secret", "/settings.py", SEVERITY_CRITICAL,
                  "Django settings file exposed",
                  body_contains="SECRET_KEY", valid_status_codes=[200]),

    ExposureCheck("actuator_env", "/actuator/env", SEVERITY_CRITICAL,
                  "Spring Boot actuator /env exposed — contains all environment variables",
                  body_contains="propertySources", valid_status_codes=[200]),

    ExposureCheck("actuator_heapdump", "/actuator/heapdump", SEVERITY_CRITICAL,
                  "Spring Boot heap dump exposed — JVM memory including tokens and passwords",
                  valid_status_codes=[200], min_size=1000),

    ExposureCheck("jenkins_script", "/jenkins/script", SEVERITY_CRITICAL,
                  "Jenkins Groovy script console accessible — potential RCE",
                  body_contains="script", valid_status_codes=[200]),

    ExposureCheck("jenkins_script_bare", "/script", SEVERITY_CRITICAL,
                  "Jenkins script console accessible without path prefix",
                  body_contains="script", valid_status_codes=[200]),

    ExposureCheck("symfony_profiler", "/_profiler", SEVERITY_CRITICAL,
                  "Symfony profiler exposed — shows full request data including POST bodies",
                  body_contains="profiler", valid_status_codes=[200]),

    ExposureCheck("yii_debug", "/debug/default/view", SEVERITY_CRITICAL,
                  "Yii debug panel exposed",
                  valid_status_codes=[200]),

    ExposureCheck("docker_compose_env", "/docker-compose.yml", SEVERITY_CRITICAL,
                  "Docker Compose file exposed — may contain credentials",
                  body_contains="services:", valid_status_codes=[200]),

    ExposureCheck("private_pem", "/server.pem", SEVERITY_CRITICAL,
                  "PEM private key exposed",
                  body_contains="PRIVATE", valid_status_codes=[200]),

    ExposureCheck("private_key", "/private.key", SEVERITY_CRITICAL,
                  "Private key file exposed",
                  body_contains="PRIVATE", valid_status_codes=[200]),

    # ---- HIGH: Sensitive Information ----
    ExposureCheck("phpinfo", "/phpinfo.php", SEVERITY_HIGH,
                  "PHP info page exposed — reveals full server configuration",
                  body_contains="PHP Version", valid_status_codes=[200]),

    ExposureCheck("info_php", "/info.php", SEVERITY_HIGH,
                  "PHP info page exposed",
                  body_contains="phpinfo()", valid_status_codes=[200]),

    ExposureCheck("apache_server_status", "/server-status", SEVERITY_HIGH,
                  "Apache server-status exposed — shows active requests and client IPs",
                  body_contains="Apache Server Status", valid_status_codes=[200]),

    ExposureCheck("apache_server_info", "/server-info", SEVERITY_HIGH,
                  "Apache server-info exposed — reveals full server configuration",
                  body_contains="Apache Server Information", valid_status_codes=[200]),

    ExposureCheck("nginx_status", "/nginx_status", SEVERITY_HIGH,
                  "Nginx status page exposed",
                  body_contains="Active connections:", valid_status_codes=[200]),

    ExposureCheck("nginx_status_alt", "/status", SEVERITY_HIGH,
                  "Server status endpoint exposed",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("actuator_root", "/actuator", SEVERITY_HIGH,
                  "Spring Boot actuator root endpoint exposed",
                  body_contains="_links", valid_status_codes=[200]),

    ExposureCheck("actuator_configprops", "/actuator/configprops", SEVERITY_HIGH,
                  "Spring Boot config properties exposed",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("actuator_beans", "/actuator/beans", SEVERITY_HIGH,
                  "Spring Boot beans list exposed",
                  body_contains="beans", valid_status_codes=[200]),

    ExposureCheck("actuator_mappings", "/actuator/mappings", SEVERITY_HIGH,
                  "Spring Boot request mappings exposed — all API endpoints visible",
                  body_contains="mappings", valid_status_codes=[200]),

    ExposureCheck("actuator_threaddump", "/actuator/threaddump", SEVERITY_HIGH,
                  "Spring Boot thread dump exposed",
                  body_contains="threads", valid_status_codes=[200]),

    ExposureCheck("actuator_logfile", "/actuator/logfile", SEVERITY_HIGH,
                  "Spring Boot log file exposed",
                  valid_status_codes=[200], min_size=50),

    ExposureCheck("actuator_metrics", "/actuator/metrics", SEVERITY_HIGH,
                  "Spring Boot metrics exposed",
                  body_contains="names", valid_status_codes=[200]),

    ExposureCheck("actuator_trace", "/actuator/httptrace", SEVERITY_HIGH,
                  "Spring Boot HTTP traces exposed — includes request/response data",
                  body_contains="traces", valid_status_codes=[200]),

    ExposureCheck("actuator_gateway", "/actuator/gateway/routes", SEVERITY_HIGH,
                  "Spring Cloud Gateway routes exposed",
                  valid_status_codes=[200]),

    ExposureCheck("swagger_ui_html", "/swagger-ui.html", SEVERITY_HIGH,
                  "Swagger UI exposed",
                  body_contains="swagger", valid_status_codes=[200]),

    ExposureCheck("swagger_ui_new", "/swagger-ui/index.html", SEVERITY_HIGH,
                  "Swagger UI (new path) exposed",
                  body_contains="swagger", valid_status_codes=[200]),

    ExposureCheck("swagger_json", "/swagger.json", SEVERITY_HIGH,
                  "Swagger/OpenAPI spec exposed",
                  body_contains="swagger", valid_status_codes=[200]),

    ExposureCheck("openapi_v3", "/v3/api-docs", SEVERITY_HIGH,
                  "OpenAPI v3 documentation exposed",
                  body_contains="openapi", valid_status_codes=[200]),

    ExposureCheck("openapi_v2", "/v2/api-docs", SEVERITY_HIGH,
                  "OpenAPI v2/Swagger documentation exposed",
                  body_contains="swagger", valid_status_codes=[200]),

    ExposureCheck("api_docs", "/api-docs", SEVERITY_HIGH,
                  "API documentation exposed",
                  valid_status_codes=[200], min_size=50),

    ExposureCheck("graphql_introspection", "/graphql", SEVERITY_HIGH,
                  "GraphQL endpoint accessible — check for introspection",
                  valid_status_codes=[200, 400], min_size=10),

    ExposureCheck("graphiql", "/graphiql", SEVERITY_HIGH,
                  "GraphiQL IDE exposed — interactive GraphQL query interface",
                  body_contains="graphiql", valid_status_codes=[200]),

    ExposureCheck("graphql_playground", "/playground", SEVERITY_HIGH,
                  "GraphQL Playground exposed",
                  body_contains="playground", valid_status_codes=[200]),

    ExposureCheck("saml_metadata", "/saml/metadata.xml", SEVERITY_HIGH,
                  "SAML metadata exposed",
                  body_contains="EntityDescriptor", valid_status_codes=[200]),

    ExposureCheck("wsdl", "/wsdl", SEVERITY_HIGH,
                  "SOAP WSDL exposed",
                  body_contains="definitions", valid_status_codes=[200]),

    ExposureCheck("oidc_discovery", "/.well-known/openid-configuration", SEVERITY_HIGH,
                  "OIDC discovery document exposed",
                  body_contains="issuer", valid_status_codes=[200]),

    ExposureCheck("elasticsearch_cluster", "/_cluster/health", SEVERITY_HIGH,
                  "Elasticsearch cluster health accessible — unauthenticated access",
                  body_contains="cluster_name", valid_status_codes=[200]),

    ExposureCheck("elasticsearch_indices", "/_cat/indices", SEVERITY_HIGH,
                  "Elasticsearch indices list accessible",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("elasticsearch_search", "/_search", SEVERITY_HIGH,
                  "Elasticsearch search endpoint accessible",
                  body_contains="hits", valid_status_codes=[200]),

    ExposureCheck("elasticsearch_nodes", "/_nodes", SEVERITY_HIGH,
                  "Elasticsearch nodes info accessible",
                  body_contains="nodes", valid_status_codes=[200]),

    ExposureCheck("solr_admin", "/solr/admin/", SEVERITY_HIGH,
                  "Apache Solr admin panel accessible",
                  body_contains="Solr Admin", valid_status_codes=[200]),

    ExposureCheck("solr_root", "/solr/", SEVERITY_HIGH,
                  "Apache Solr accessible",
                  valid_status_codes=[200]),

    ExposureCheck("kibana_app", "/app/kibana", SEVERITY_HIGH,
                  "Kibana dashboard accessible",
                  valid_status_codes=[200, 302]),

    ExposureCheck("prometheus_metrics", "/metrics", SEVERITY_HIGH,
                  "Prometheus metrics endpoint exposed — may contain sensitive data",
                  body_contains="# HELP", valid_status_codes=[200]),

    ExposureCheck("git_log", "/.git/logs/HEAD", SEVERITY_HIGH,
                  "Git commit log exposed",
                  body_contains="commit", valid_status_codes=[200]),

    # ---- HIGH: Admin Panels ----
    ExposureCheck("tomcat_manager", "/manager/html", SEVERITY_HIGH,
                  "Tomcat manager accessible",
                  body_contains="Tomcat", valid_status_codes=[200, 401, 403]),

    ExposureCheck("tomcat_hostmanager", "/host-manager/html", SEVERITY_HIGH,
                  "Tomcat host manager accessible",
                  valid_status_codes=[200, 401, 403]),

    ExposureCheck("jboss_jmx", "/jmx-console/", SEVERITY_HIGH,
                  "JBoss JMX console accessible",
                  body_contains="JMX", valid_status_codes=[200, 401]),

    ExposureCheck("jboss_webconsole", "/web-console/", SEVERITY_HIGH,
                  "JBoss web console accessible",
                  valid_status_codes=[200, 401]),

    ExposureCheck("phpmyadmin", "/phpmyadmin/", SEVERITY_HIGH,
                  "phpMyAdmin accessible",
                  body_contains="phpMyAdmin", valid_status_codes=[200]),

    ExposureCheck("phpmyadmin_alt", "/pma/", SEVERITY_HIGH,
                  "phpMyAdmin (alternate path) accessible",
                  body_contains="phpMyAdmin", valid_status_codes=[200]),

    ExposureCheck("jenkins_main", "/jenkins/", SEVERITY_HIGH,
                  "Jenkins accessible",
                  body_contains="Jenkins", valid_status_codes=[200]),

    ExposureCheck("grafana_login", "/login", SEVERITY_HIGH,
                  "Login page accessible — check for default credentials",
                  valid_status_codes=[200], min_size=100),

    ExposureCheck("docker_registry", "/v2/_catalog", SEVERITY_HIGH,
                  "Docker registry catalog accessible — lists all images",
                  body_contains="repositories", valid_status_codes=[200]),

    ExposureCheck("portainer", "/#/auth", SEVERITY_HIGH,
                  "Portainer Docker management accessible",
                  valid_status_codes=[200]),

    ExposureCheck("k8s_api", "/api/v1", SEVERITY_HIGH,
                  "Kubernetes API accessible",
                  body_contains="kind", valid_status_codes=[200, 401, 403]),

    ExposureCheck("rabbitmq_api", "/api/", SEVERITY_HIGH,
                  "RabbitMQ management API accessible",
                  body_contains="rabbitmq", valid_status_codes=[200, 401]),

    ExposureCheck("couchdb", "/_utils/", SEVERITY_HIGH,
                  "CouchDB Fauxton UI accessible",
                  body_contains="CouchDB", valid_status_codes=[200]),

    # ---- MEDIUM: Information Disclosure ----
    ExposureCheck("robots_txt", "/robots.txt", SEVERITY_MEDIUM,
                  "robots.txt — may reveal hidden endpoints",
                  body_contains="Disallow", valid_status_codes=[200]),

    ExposureCheck("sitemap", "/sitemap.xml", SEVERITY_MEDIUM,
                  "Sitemap — full site map",
                  body_contains="<?xml", valid_status_codes=[200]),

    ExposureCheck("crossdomain", "/crossdomain.xml", SEVERITY_MEDIUM,
                  "Flash cross-domain policy exposed",
                  body_contains="cross-domain-policy", valid_status_codes=[200]),

    ExposureCheck("security_txt", "/.well-known/security.txt", SEVERITY_LOW,
                  "security.txt present",
                  valid_status_codes=[200], min_size=20),

    ExposureCheck("changelog", "/CHANGELOG.txt", SEVERITY_MEDIUM,
                  "Changelog exposed — reveals exact software version",
                  valid_status_codes=[200], min_size=50),

    ExposureCheck("changelog_md", "/CHANGELOG.md", SEVERITY_MEDIUM,
                  "Changelog (MD) exposed",
                  valid_status_codes=[200], min_size=50),

    ExposureCheck("readme", "/README.md", SEVERITY_LOW,
                  "README.md exposed",
                  valid_status_codes=[200], min_size=50),

    ExposureCheck("version_file", "/VERSION", SEVERITY_MEDIUM,
                  "VERSION file exposed — reveals exact version",
                  valid_status_codes=[200], min_size=3),

    ExposureCheck("build_json", "/build.json", SEVERITY_MEDIUM,
                  "Build info JSON exposed",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("package_json", "/package.json", SEVERITY_MEDIUM,
                  "package.json exposed — reveals dependencies for vulnerability research",
                  body_contains="dependencies", valid_status_codes=[200]),

    ExposureCheck("composer_json", "/composer.json", SEVERITY_MEDIUM,
                  "composer.json exposed",
                  body_contains="require", valid_status_codes=[200]),

    ExposureCheck("requirements_txt", "/requirements.txt", SEVERITY_MEDIUM,
                  "Python requirements exposed",
                  valid_status_codes=[200], min_size=20),

    ExposureCheck("pom_xml", "/pom.xml", SEVERITY_MEDIUM,
                  "Maven pom.xml exposed",
                  body_contains="<project>", valid_status_codes=[200]),

    ExposureCheck("dockerfile", "/Dockerfile", SEVERITY_MEDIUM,
                  "Dockerfile exposed",
                  body_contains="FROM", valid_status_codes=[200]),

    ExposureCheck("docker_config_json", "/.docker/config.json", SEVERITY_CRITICAL,
                  "Docker registry auth config exposed — may contain credentials",
                  body_contains="auths", valid_status_codes=[200]),

    ExposureCheck("procfile", "/Procfile", SEVERITY_LOW,
                  "Heroku Procfile exposed",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("wp_admin", "/wp-admin/", SEVERITY_MEDIUM,
                  "WordPress admin panel accessible",
                  valid_status_codes=[200, 302]),

    ExposureCheck("wp_login", "/wp-login.php", SEVERITY_MEDIUM,
                  "WordPress login accessible",
                  body_contains="wp-login", valid_status_codes=[200]),

    ExposureCheck("wp_json", "/wp-json/", SEVERITY_MEDIUM,
                  "WordPress REST API exposed",
                  body_contains="namespace", valid_status_codes=[200]),

    ExposureCheck("xmlrpc", "/xmlrpc.php", SEVERITY_MEDIUM,
                  "WordPress XML-RPC exposed — potential brute force vector",
                  valid_status_codes=[200, 405]),

    ExposureCheck("drupal_admin", "/admin/", SEVERITY_MEDIUM,
                  "Drupal admin accessible",
                  valid_status_codes=[200, 302]),

    ExposureCheck("git_objects", "/.git/objects/info/packs", SEVERITY_CRITICAL,
                  "Git pack files accessible — entire repo downloadable",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("svn_entries", "/.svn/entries", SEVERITY_HIGH,
                  "SVN repository entries exposed",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("svn_wc", "/.svn/wc.db", SEVERITY_HIGH,
                  "SVN working copy database exposed",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("htpasswd", "/.htpasswd", SEVERITY_CRITICAL,
                  "Apache .htpasswd file exposed — contains password hashes",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("htaccess", "/.htaccess", SEVERITY_HIGH,
                  "Apache .htaccess exposed — reveals server configuration",
                  body_contains="RewriteRule", valid_status_codes=[200]),

    ExposureCheck("config_yml", "/config.yml", SEVERITY_HIGH,
                  "YAML config file exposed",
                  valid_status_codes=[200], min_size=20),

    ExposureCheck("config_yaml", "/config.yaml", SEVERITY_HIGH,
                  "YAML config file exposed",
                  valid_status_codes=[200], min_size=20),

    ExposureCheck("application_yml", "/application.yml", SEVERITY_HIGH,
                  "Spring Boot application.yml exposed",
                  valid_status_codes=[200], min_size=20),

    ExposureCheck("application_properties", "/application.properties", SEVERITY_HIGH,
                  "Spring Boot application.properties exposed",
                  valid_status_codes=[200], min_size=20),

    ExposureCheck("web_config", "/web.config", SEVERITY_HIGH,
                  "ASP.NET web.config exposed",
                  body_contains="configuration", valid_status_codes=[200]),

    ExposureCheck("trace_axd", "/trace.axd", SEVERITY_HIGH,
                  "ASP.NET trace viewer exposed",
                  valid_status_codes=[200]),

    ExposureCheck("elmah", "/elmah.axd", SEVERITY_HIGH,
                  "ELMAH error log viewer exposed",
                  body_contains="elmah", valid_status_codes=[200]),

    # ---- LOW: Information disclosure ----
    ExposureCheck("humans_txt", "/humans.txt", SEVERITY_LOW,
                  "humans.txt — team information",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("security_txt_root", "/security.txt", SEVERITY_LOW,
                  "security.txt present at root",
                  valid_status_codes=[200], min_size=10),

    ExposureCheck("gemfile", "/Gemfile", SEVERITY_LOW,
                  "Ruby Gemfile exposed",
                  body_contains="gem ", valid_status_codes=[200]),

    ExposureCheck("makefile", "/Makefile", SEVERITY_LOW,
                  "Makefile exposed",
                  valid_status_codes=[200], min_size=20),

    ExposureCheck("api_version", "/api/version", SEVERITY_LOW,
                  "API version endpoint — reveals version info",
                  valid_status_codes=[200], min_size=5),

    ExposureCheck("health_endpoint", "/health", SEVERITY_LOW,
                  "Health endpoint accessible",
                  valid_status_codes=[200], min_size=5),

    ExposureCheck("actuator_health", "/actuator/health", SEVERITY_LOW,
                  "Spring Boot health endpoint",
                  body_contains="status", valid_status_codes=[200]),
]

# Group by severity for easy access
CHECKS_BY_SEVERITY = {
    SEVERITY_CRITICAL: [c for c in ALL_CHECKS if c.severity == SEVERITY_CRITICAL],
    SEVERITY_HIGH: [c for c in ALL_CHECKS if c.severity == SEVERITY_HIGH],
    SEVERITY_MEDIUM: [c for c in ALL_CHECKS if c.severity == SEVERITY_MEDIUM],
    SEVERITY_LOW: [c for c in ALL_CHECKS if c.severity == SEVERITY_LOW],
}

# Index by name for fast lookup
CHECKS_BY_NAME = {c.name: c for c in ALL_CHECKS}
