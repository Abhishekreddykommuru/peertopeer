# =============================================================================
# client/Makefile — builds ./client/client
# (see tracker/Makefile for flag rationale)
# =============================================================================
CXX      ?= g++
CXXFLAGS := -std=c++17 -O2 -g -Wall -Wextra -pthread -I../common/include
LDFLAGS  := -pthread

COMMON_SRC := $(wildcard ../common/src/*.cpp)
SRC        := $(wildcard src/*.cpp)
OBJ        := $(SRC:src/%.cpp=build/%.o) \
              $(COMMON_SRC:../common/src/%.cpp=build/common_%.o)

client: $(OBJ)
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

build/%.o: src/%.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/common_%.o: ../common/src/%.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build:
	mkdir -p build

.PHONY: clean
clean:
	rm -rf build client
