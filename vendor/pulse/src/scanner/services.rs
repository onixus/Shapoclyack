/// Well-known TCP service names (subset of IANA + common apps).
pub fn service_name(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp-client",
        69 => "tftp",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        179 => "bgp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        500 => "isakmp",
        514 => "syslog",
        515 => "printer",
        520 => "rip",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        989 => "ftps-data",
        990 => "ftps",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1194 => "openvpn",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 => "docker",
        2376 => "docker-tls",
        3000 => "dev-http",
        3306 => "mysql",
        3389 => "rdp",
        4443 => "https-alt",
        4500 => "ipsec-nat",
        5000 => "upnp/flask",
        5432 => "postgresql",
        5601 => "kibana",
        5672 => "amqp",
        5900 => "vnc",
        5984 => "couchdb",
        6379 => "redis",
        6443 => "k8s-api",
        6667 => "irc",
        7001 => "weblogic",
        8000 => "http-alt",
        8008 => "http-alt",
        8080 => "http-proxy",
        8081 => "http-alt",
        8443 => "https-alt",
        8888 => "http-alt",
        9000 => "sonarqube",
        9090 => "prometheus",
        9200 => "elasticsearch",
        9300 => "es-transport",
        9418 => "git",
        11211 => "memcached",
        27017 => "mongodb",
        27018 => "mongodb-shard",
        50000 => "sap",
        _ => "unknown",
    }
}

/// Most commonly scanned / useful TCP ports (Nmap top-ish order).
pub fn top_ports(n: usize) -> Vec<u16> {
    const TOP: &[u16] = &[
        80, 443, 22, 21, 25, 53, 110, 139, 143, 445, 3389, 3306, 8080, 23, 135,
        445, 993, 995, 1723, 111, 995, 5900, 1025, 587, 8888, 199, 1720, 465,
        548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768,
        554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000,
        5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155,
        6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009,
        3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029,
        9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
        1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801,
        5050, 19, 1041, 3703, 17, 5003, 808, 1048, 1049, 2967, 1053, 3703,
        1054, 3703, 1056, 1044, 999, 1051, 1032, 1031, 1033, 1035, 50000,
        27017, 6379, 11211, 9200, 5601, 2375, 6443, 2181, 5672, 1883, 9418,
        7001, 1521, 5984, 9300, 4500, 500, 1194, 1080, 2222, 4443, 8444, 9443,
    ];

    let mut ports: Vec<u16> = TOP.iter().copied().take(n.max(1)).collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Common UDP service names.
pub fn udp_service_name(port: u16) -> &'static str {
    match port {
        53 => "dns",
        67 => "dhcp",
        68 => "dhcp-client",
        69 => "tftp",
        123 => "ntp",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        161 => "snmp",
        162 => "snmptrap",
        500 => "isakmp",
        514 => "syslog",
        520 => "rip",
        1194 => "openvpn",
        1900 => "ssdp",
        4500 => "ipsec-nat",
        5353 => "mdns",
        11211 => "memcached",
        _ => service_name(port),
    }
}

/// Common UDP ports for `--top` when scanning UDP.
pub fn top_udp_ports(n: usize) -> Vec<u16> {
    const TOP: &[u16] = &[
        53, 123, 161, 137, 138, 67, 68, 69, 500, 4500, 514, 520, 1900, 5353, 1194,
        162, 1434, 5060, 33434, 11211, 2049, 111, 389, 636, 88, 464, 1812, 1813,
        1701, 5004, 5005, 3478, 19302, 27015, 7777, 27005, 3074, 9000, 3702,
    ];
    let mut ports: Vec<u16> = TOP.iter().copied().take(n.max(1)).collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}
