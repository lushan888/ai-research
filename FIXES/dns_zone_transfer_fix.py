"""
DNS Zone Transfer Enabled → Internal Network Mapping Fix
Bounty #806 ($150)
=========================================
Vulnerability: DNS server allows AXFR (Zone Transfer) from any IP.
Attacker downloads all DNS records, identifies internal servers.

Fix: Restrict AXFR to trusted slaves + TSIG signature.
"""


class SecureDNSConfig:
    """
    Secure DNS configuration to prevent zone transfer leaks.
    """

    # BIND named.conf options
    BIND_SECURE_CONFIG = """
# BIND named.conf - Secure Zone Transfer Configuration

options {
    directory "/var/named";
    
    # Allow queries only from internal networks
    allow-query { 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; };
    
    # Disable recursion for external queries
    recursion no;
    
    # Enable DNSSEC
    dnssec-enable yes;
    dnssec-validation yes;
    
    # Hide version
    version "not available";
};

# Internal zone - restricted zone transfer
zone "example.com" IN {
    type master;
    file "example.com.zone";
    
    # Only allow zone transfer to specific slave servers
    allow-transfer { 
        10.0.1.10;   # Primary slave
        10.0.1.11;   # Secondary slave
        10.0.1.12;   # Backup slave
    };
    
    # Allow dynamic updates only from trusted IPs
    allow-update { none; };
    
    # Also-notify to slaves
    also-notify { 10.0.1.10; 10.0.1.11; };
};

# Internal zone - no zone transfer (hidden)
zone "internal.example.com" IN {
    type master;
    file "internal.example.com.zone";
    
    # No zone transfer allowed
    allow-transfer { none; };
    
    # Not published in public DNS
};

# Public zone - limited records only
zone "public.example.com" IN {
    type master;
    file "public.example.com.zone";
    
    # Zone transfer only to authorized DNS providers
    allow-transfer { 
        203.0.113.10;  # DNS provider 1
        203.0.113.11;  # DNS provider 2
    };
};
"""

    # TSIG key configuration
    TSIG_CONFIG = """
# TSIG key for authenticated zone transfers
key "zone-transfer-key.example.com" {
    algorithm hmac-sha256;
    secret "BASE64_ENCODED_SECRET_KEY_HERE";
};

# Apply TSIG to zone transfer
zone "example.com" IN {
    type master;
    file "example.com.zone";
    
    # TSIG-authenticated zone transfer
    allow-transfer { 
        key "zone-transfer-key.example.com";
    };
};
"""

    @staticmethod
    def restrict_axfr(allowed_ips: list) -> dict:
        """Generate zone transfer restriction config."""
        return {
            "axfr_enabled": True,
            "axfr_restricted": True,
            "allowed_transfer_ips": allowed_ips,
            "tsig_required": True,
            "tsig_algorithm": "hmac-sha256",
        }

    @staticmethod
    def split_horizon_config(public_records: dict,
                             internal_records: dict) -> dict:
        """Split-horizon DNS configuration."""
        return {
            "public_zone": {
                "records": public_records,
                "view": "external",
                "allow_transfer": ["203.0.113.10"],
            },
            "internal_zone": {
                "records": internal_records,
                "view": "internal",
                "allow_transfer": ["10.0.1.10", "10.0.1.11"],
            },
        }


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== DNS Zone Transfer Prevention ===")
    print()

    print("Attack scenario:")
    print("  dig axfr @ns1.example.com example.com")
    print("  → Attacker downloads ALL DNS records!")
    print("  → Maps internal network topology")
    print()

    config = SecureDNSConfig.restrict_axfr(["10.0.1.10", "10.0.1.11"])
    print("Secure config:")
    for k, v in config.items():
        print(f"  ✓ {k}: {v}")
    print()
    print("Measures:")
    print("✓ AXFR restricted to specific slave IPs")
    print("✓ TSIG signature required")
    print("✓ Split-horizon DNS (public vs internal)")
    print("✓ Internal zones: allow-transfer { none; }")
    print("✓ DNSSEC enabled")
    print("✓ Recursion disabled for external queries")