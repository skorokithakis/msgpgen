all: msgpgen.xpi

clean:
	rm msgpgen.xpi || true

.PHONY: msgpgen.xpi
msgpgen.xpi: clean
	zip -r msgpgen.xpi *


