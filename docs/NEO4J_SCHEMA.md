# Neo4j Knowledge Graph Schema

## Node Labels

### Host
Represents a discovered network host (IP address).

```cypher
CREATE CONSTRAINT host_ip_unique IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE
```

**Properties:**
| Property | Type | Description |
|----------|------|-------------|
| `ip` | String | IP address (unique key) |
| `hostname` | String | Resolved hostname |
| `os` | String | Operating system |
| `status` | String | `up` / `down` / `unknown` |
| `tags` | String[] | Arbitrary tags |
| `first_seen` | Integer | Unix timestamp |
| `last_seen` | Integer | Unix timestamp |

---

### Domain
Represents a DNS domain name.

```cypher
CREATE CONSTRAINT domain_name_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE
```

**Properties:**
| Property | Type | Description |
|----------|------|-------------|
| `name` | String | FQDN (unique key) |
| `registrar` | String | Domain registrar |
| `created_at` | Integer | Unix timestamp |

---

### Service
Represents a network service running on a host.

**Properties:**
| Property | Type | Description |
|----------|------|-------------|
| `name` | String | Service name (e.g. `nginx`, `apache`) |
| `version` | String | Version string |
| `protocol` | String | `http` / `https` / `ftp` / etc. |
| `port` | Integer | Port number |
| `state` | String | `open` / `closed` / `filtered` |
| `banner` | String | Service banner |

---

### Technology
Represents a technology identified via fingerprinting (Wappalyzer, etc.).

```cypher
CREATE INDEX tech_name_idx IF NOT EXISTS FOR (t:Technology) ON (t.name)
```

**Properties:**
| Property | Type | Description |
|----------|------|-------------|
| `name` | String | Technology name (e.g. `WordPress`, `React`) |
| `version` | String | Detected version |
| `category` | String | `CMS` / `Framework` / `Server` / `Language` / etc. |
| `confidence` | Integer | Detection confidence 0-100 |

---

### Vulnerability
Represents a confirmed or potential vulnerability.

```cypher
CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE
```

**Properties:**
| Property | Type | Description |
|----------|------|-------------|
| `id` | String | Unique ID (unique key) |
| `template_id` | String | Nuclei template ID |
| `name` | String | Vulnerability name |
| `severity` | String | `critical` / `high` / `medium` / `low` / `info` |
| `status` | String | `potential` / `confirmed` / `false_positive` / `exploited` |
| `target` | String | Affected URL |
| `matched_at` | String | Precise match location |
| `description` | String | Description |
| `tags` | String[] | Tags |
| `discovered_at` | Integer | Unix timestamp |

---

### Credential
Represents an extracted credential or token.

**Properties:**
| Property | Type | Description |
|----------|------|-------------|
| `type` | String | `username` / `password` / `token` / `apikey` / `cookie` |
| `value` | String | Credential value (sensitive) |
| `context` | String | Discovery context / location |
| `source` | String | Source template ID |
| `verified` | Boolean | Whether credential has been verified |

---

## Relationships

| Relationship | From | To | Description |
|-------------|------|----|-------------|
| `RUNS` | Host | Technology | Host runs this technology |
| `EXPOSES` | Host | Service | Host exposes this service |
| `HAS_ENDPOINT` | Service | Endpoint | Service has this endpoint |
| `AFFECTS` | Vulnerability | Host | Vulnerability affects this host |
| `EXPOSES_TOKEN` | Host | Credential | Host leaks this credential |
| `AUTHENTICATES_WITH` | Credential | Service | Credential authenticates to service |
| `PART_OF` | Domain | Host | Domain resolves to host |
| `DISCOVERED_BY` | Vulnerability | Vulnerability | One vuln discovery led to another |
| `LINKS_TO` | Endpoint | Endpoint | Redirect or reference chain |

---

## Example Cypher Queries

### Find all hosts running a specific technology
```cypher
MATCH (h:Host)-[:RUNS]->(t:Technology {name: "WordPress"})
RETURN h.ip, h.hostname, t.version
```

### Find vulnerabilities and their extracted credentials
```cypher
MATCH (v:Vulnerability)-[:AFFECTS]->(h:Host)-[:EXPOSES_TOKEN]->(c:Credential)
WHERE v.severity IN ["critical", "high"]
RETURN v.name, v.severity, h.ip, c.type, c.context
ORDER BY v.severity DESC
```

### Find attack chain: tech → vuln → credential
```cypher
MATCH (h:Host)-[:RUNS]->(t:Technology)
MATCH (v:Vulnerability)-[:AFFECTS]->(h)
MATCH (h)-[:EXPOSES_TOKEN]->(c:Credential)
RETURN h.ip, t.name, t.version, v.name, v.severity, c.type
ORDER BY v.severity
```

### Find all high-severity vulnerabilities in a session
```cypher
MATCH (v:Vulnerability)
WHERE v.severity IN ["critical", "high"] AND v.status = "confirmed"
RETURN v.id, v.name, v.severity, v.target
ORDER BY v.severity DESC
```

---

## Schema Initialization

The `Neo4jClient.InitSchema()` method (in `pkg/storage/neo4j_client.go`) automatically
creates all required constraints and indexes on first connection.
