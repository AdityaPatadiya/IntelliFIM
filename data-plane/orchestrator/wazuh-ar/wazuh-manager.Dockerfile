# data-plane/orchestrator/wazuh-ar/wazuh-manager.Dockerfile
#
# UNUSED IN v1 (kept as documentation of the original Wazuh `<include>` approach).
# The `quarantine` AR command is now inlined directly into
# `data-plane/wazuh/manager/ossec.conf` (which is volume-mounted via
# /wazuh-config-mount), because (1) the existing compose's mount silently
# shadows ANY image-baked ossec.conf changes, and (2) `wazuh-csyslogd` rejects
# the `<include>` directive. v2 cleanup: delete this file.
#
# Original intent (preserved for documentation):
# Custom wazuh-manager image that bakes the IntelliFIM `quarantine` AR command
# definition into the manager's ossec.conf.
#
# The upstream wazuh-manager image's entrypoint copies the in-image
# /var/ossec/etc/ossec.conf to the persisted volume on first start (when
# the volume is empty). By modifying ossec.conf at image-build time, our
# fresh-checkout DoD (which always runs `down -v` first) gets the patched
# config on every clean start.
FROM wazuh/wazuh-manager:4.14.5

# IMPORTANT: The upstream wazuh-manager entrypoint (/etc/cont-init.d/0-wazuh-init)
# populates the persisted /var/ossec/etc/ volume from the in-image BACKUP at
# /var/ossec/data_tmp/permanent/var/ossec/etc/ on FIRST start. Patching only the
# active path is silently overwritten on first start — we MUST patch the backup
# (and we also patch the active path so manual `docker run` without compose
# still picks it up).
COPY intellifim-orchestrator.conf /var/ossec/etc/intellifim-orchestrator.conf
COPY intellifim-orchestrator.conf /var/ossec/data_tmp/permanent/var/ossec/etc/intellifim-orchestrator.conf

# Patch BOTH the active ossec.conf AND the data_tmp backup. The sed range
# `0,/pattern/` matches only the FIRST `</ossec_config>` (upstream ossec.conf
# has two top-level <ossec_config> blocks; we only need one <include>). The
# outer `grep -q` guard makes each patch idempotent across rebuilds.
RUN grep -q "intellifim-orchestrator.conf" /var/ossec/etc/ossec.conf || \
    sed -i '0,/<\/ossec_config>/{s|</ossec_config>|  <include>intellifim-orchestrator.conf</include>\n</ossec_config>|}' \
        /var/ossec/etc/ossec.conf && \
    grep -q "intellifim-orchestrator.conf" /var/ossec/data_tmp/permanent/var/ossec/etc/ossec.conf || \
    sed -i '0,/<\/ossec_config>/{s|</ossec_config>|  <include>intellifim-orchestrator.conf</include>\n</ossec_config>|}' \
        /var/ossec/data_tmp/permanent/var/ossec/etc/ossec.conf
