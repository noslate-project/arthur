CC := g++
CCFLAGS += -std=c++11 -Wall -g -O2
LDFLAGS += -Wl,--gc-sections -Wl,--as-needed -Llib -llz4 -ldl 

GIT_VERSION := $(shell git describe --abbrev=6 --dirty --always --tags)

SRC := \
	src/core.cc \
	src/proc.cc \
	src/lz4.cc \
	src/arthur.cc

OBJ := $(SRC:src/%.cc=build/%.o)
DEP := $(OBJ:%.o=%.d)
INC := -Iinclude
DEF := -DGIT_VERSION=\"$(GIT_VERSION)\" 
TARGET = arthur
TARGET_G = arthur_g
PACKAGE = Arthur-$(GIT_VERSION)-$(shell uname -s)-$(shell uname -p).tar.gz
PACKAGE_G = Arthur-$(GIT_VERSION)-$(shell uname -s)-$(shell uname -p)-Debug.tar.gz

.PHONY: clean all test cleanall distclean package
.SUFFIXES:
.SECONDARY:

all: $(TARGET)

build/$(TARGET_G): $(OBJ)
	@echo LINK $(notdir $@)
	@$(CC) $(CCFLAGS) -o $@ $(OBJ) $(LDFLAGS)

build/$(TARGET): build/$(TARGET_G)
	@strip $< -o $@

$(TARGET): build/$(TARGET)
	@ln -sf build/$(TARGET) $@

build/%.o: src/%.cc
	@echo CC $<
	@mkdir -p $(dir $@)
	@$(CC) $(CCFLAGS) $(INC) $(DEF) -MMD -MT $@ -MF build/$*.d -o $@ -c $<

test:
	@echo TBD

clean:
	@rm -rf build $(TARGET)
	@rm -rf Arthur-*.tar.gz

cleanall: clean

distclean: cleanall

host.log: $(TARGET) 
	@sh -c "uname -a; cat /etc/*release; ldd ./arthur" > $@

$(PACKAGE): $(TARGET)
	@echo $@
	@tar cfz $(PACKAGE) build/arthur 

$(PACKAGE_G): $(TARGET) host.log
	@echo $@
	@tar cfz $(PACKAGE_G) build/arthur build/arthur_g host.log 

package: $(PACKAGE) $(PACKAGE_G)
	@echo $*

-include $(DEP)
