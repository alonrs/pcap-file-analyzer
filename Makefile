SRC_DIR    ?= src
BIN_DIR    ?= bin
COMMON_DIR ?= libcommon
CC         ?= gcc
CXX        ?= g++
CFLAGS     := -std=gnu11 -Wall -I. -fpic 
CXXFLAGS   := -std=c++11 -Wall -I. -fpic
LDFLAGS    := -lpthread -lm -lpcap
CXXLINK    := $(CXX)

# Make sure that libcommon exists
ifeq "$(wildcard $(COMMON_DIR) )" ""
$(error "Cannot make project; did you run ./build.sh?")
endif

# Include all user-defined functions
include $(COMMON_DIR)/functions.mk

# Create rules for all object files
$(call createmodule_cpp,$(wildcard $(SRC_DIR)/*.cpp),src)
$(call createmodule_c,$(wildcard $(COMMON_DIR)/lib/*.c),common) 

# Search for all objects, executables
SRC_OBJ:=$(call collectobjects,$(SRC_DIR),$(BIN_DIR),cpp,util)
COMMON_OBJ:=$(call collectobjects,$(COMMON_DIR)/lib,$(BIN_DIR),c)

APPS:=$(call collectexecutables,$(SRC_DIR),$(BIN_DIR),cpp,util-)

release: $(APPS) 
debug:   $(APPS)

$(BIN_DIR)/util-%.exe: $(BIN_DIR)/util-%.o $(SRC_OBJ) $(COMMON_OBJ)
	$(CXXLINK) $(CXXFLAGS) $(EXEFLAGS) $+ -o $@ $(LDFLAGS)

# Include submodule with rules to create objects
include $(BIN_DIR)/*.mk

# Target specific variables
release:    CFLAGS   += -O2 -DNDEBUG
release:    CXXFLAGS += -O2 -DNDEBUG
debug:   CFLAGS   += -Og -g
debug:   CXXFLAGS += -Og -g

clean:
	rm -rf $(BIN_DIR)

