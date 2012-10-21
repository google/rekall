# This generates HTML documentation from the txt files in this directory. You
# will need to have asciidoc installed first (apt-get install asciidoc). Then
# type make in this directory.

# All html files depend on their respective txt files.
html_files := $(patsubst %.txt,%.html,$(wildcard *.txt))

all: $(html_files)

%.html: %.txt
	asciidoc -a icons -a iconsdir=../../images/icons -b blogger $(<F)

.PHONY: clean
clean:
	rm *.html