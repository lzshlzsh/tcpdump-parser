.PHONY: all clean

subdir := $(dir $(shell find . -maxdepth 2 -mindepth 2 -name ?akefile))

all:
	@set -e
	@for i in ${subdir}; do \
		${MAKE} -C $$i || exit 1; \
		done

clean:
	@set -e
	@for i in ${subdir}; do \
		${MAKE} -C $$i clean || exit 1; \
		done
