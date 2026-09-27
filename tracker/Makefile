# =============================================================================
# tracker/Makefile — builds ./tracker/tracker
#
# -Wall -Wextra: warnings are treated as design feedback, the build must be
#                clean.
# -pthread     : std::thread maps onto pthreads on Linux/macOS.
# -O2 -g       : optimised but still debuggable (assignment runs valgrind).
# =============================================================================
CXX      ?= g++
CXXFLAGS := -std=c++17 -O2 -g -Wall -Wextra -pthread -I../common/include
LDFLAGS  := -pthread

COMMON_SRC := $(wildcard ../common/src/*.cpp)
SRC        := $(wildcard src/*.cpp)
OBJ        := $(SRC:src/%.cpp=build/%.o) \
              $(COMMON_SRC:../common/src/%.cpp=build/common_%.o)

tracker: $(OBJ)
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

build/%.o: src/%.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/common_%.o: ../common/src/%.cpp | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build:
	mkdir -p build

.PHONY: clean
clean:
	rm -rf build tracker
