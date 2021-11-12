# borrowed from
# https://github.com/kwantam/bls_sigs_ref/blob/master/sage-impl/Makefile

H2C_DIR := ./draft-irtf-cfrg-hash-to-curve/poc/
VOPRF_DIR := ./draft-irtf-voprf/poc/

SAGEFILES := $(basename $(notdir $(wildcard *.sage))) \
             $(basename $(notdir $(wildcard $(H2C_DIR)/*.sage))) \
             $(basename $(notdir $(wildcard $(VOPRF_DIR)/*.sage)))
             
             
PYFILES := $(addprefix sagelib/, $(addsuffix .py,$(SAGEFILES)))
.PRECIOUS: $(PYFILES)

.PHONY: pyfiles
pyfiles: sagelib/__init__.py $(PYFILES)

print:
#	echo $(wildcard ./draft-irtf-cfrg-hash-to-curve/poc/*.sage)
#	echo $(wildcard $(H2C_DIR)*.sage)
	echo $(SAGEFILES)
	
sagelib/__init__.py:
	mkdir -p sagelib
	echo pass > sagelib/__init__.py

sagelib/%.py: %.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

sagelib/%.py: $(H2C_DIR)%.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

sagelib/%.py: $(VOPRF_DIR)%.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

test: pyfiles
	sage test.sage

vectors: pyfiles
	@mkdir -p vectors ascii
	sage test_vectors.sage

.PHONY: clean
clean:
	rm -rf sagelib *.pyc *.sage.py *.log __pycache__

.PHONY: distclean
distclean: clean
	rm -rf vectors ascii
