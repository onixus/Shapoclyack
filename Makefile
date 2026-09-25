# Operator shortcuts. Each target is a thin wrapper over the script it names;
# the scripts are the interface, and work the same without make.

ENRICHMENT_BUILD_DIR ?= build/enrichment
ENRICHMENT_BUNDLE ?= dist/enrichment-bundle.tar.gz

.PHONY: enrichment-bundle enrichment-bundle-verify

# Refresh every enrichment feed on this (connected) host and pack the result
# into one verifiable tarball for an air-gapped installation (#339,
# docs/air-gap.md). A source that was unreachable is a warning — the bundle
# records it — unless ENRICHMENT_STRICT=1.
enrichment-bundle:
	ENRICHMENT_BUILD_DIR="$(ENRICHMENT_BUILD_DIR)" ENRICHMENT_BUNDLE="$(ENRICHMENT_BUNDLE)" \
		scripts/build-enrichment-bundle.sh || { status=$$?; \
		[ "$$status" -eq 1 ] && [ "$(ENRICHMENT_STRICT)" != "1" ] || exit $$status; }

# Check a bundle the way the loader will, without installing it.
enrichment-bundle-verify:
	python3 scripts/enrichment_bundle.py verify "$(ENRICHMENT_BUNDLE)"
