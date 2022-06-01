DEPS=Makefile $(wildcard *.sty) $(wildcard *.cls)
BUILDDIR=build

DOCUMENT=main
LATEXOPTS=-interaction=nonstopmode -shell-escape -file-line-error
LATEXMKOPTS=-outdir=${BUILDDIR} -norc -use-make -latexoption=${LATEXOPTS}

all: pdf

pdf: $(DOCUMENT).pdf

$(DOCUMENT).pdf: $(wildcard */*.tex) $(wildcard *.bib) $(DEPS)
	latexmk -pdf ${LATEXMKOPTS} ${DOCUMENT}.tex

clean:
	latexmk -c ${LATEXMKOPTS}

dist-clean:
	latexmk -C ${LATEXMKOPTS}
	${RM} $(wildcard ${BUILDDIR}/*)

