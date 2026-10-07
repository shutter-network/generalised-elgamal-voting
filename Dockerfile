# Single image for every shutter_governance_protocol service. The service a container runs is chosen by
# its `command` (python -m shutter_governance_protocol.services.<name>); the data-layer backend is chosen
# by SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER. See RUNNING.md.
FROM python:3.13-slim

WORKDIR /app

# Install deps first (layer-cached) from the manifest, then the source.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir -e '.[db,keyper,chain]'

# Deployment helper scripts (generate identities, deploy the registry).
COPY scripts ./scripts

# Default entrypoint is the uniform data-layer service; overridden per service.
CMD ["python", "-m", "shutter_governance_protocol.services.data_layer"]
