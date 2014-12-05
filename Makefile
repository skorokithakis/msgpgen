all: msgpgen.xpi

.PHONY: msgpgen.xpi
msgpgen.xpi:
	rm msgpgen.xpi || true
	zip -r msgpgen.xpi *


