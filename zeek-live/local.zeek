# Enable connection logging (conn.log) and write logs as JSON.
# Place this file in the directory where you run Zeek.

@load base/protocols/conn

# Enable DNS and HTTP logs for enrichment/temporal features.
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/http

# WSL2 / virtual NICs often show checksum-offloading artifacts.
# This avoids Zeek discarding packets due to invalid checksums.
redef ignore_checksums = T;

# Write ASCII logs as JSON objects (one JSON record per line)
redef LogAscii::use_json = T;

# Optional: reduce extra metadata headers in the log stream
redef LogAscii::include_meta = F;

# Optional: keep longer rotation interval so the detector can tail a stable file
# (Change as you prefer; rotation is still handled by the Python tailer)
redef Log::default_rotation_interval = 1hr;
