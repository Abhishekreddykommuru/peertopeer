# =============================================================================
# Top-level Makefile — builds the tracker and the client.
#
#   make          build both programs
#   make clean    remove all build artefacts
# =============================================================================

.PHONY: all tracker client clean

all: tracker client

tracker:
	$(MAKE) -C tracker

client:
	$(MAKE) -C client

clean:
	$(MAKE) -C tracker clean
	$(MAKE) -C client clean
