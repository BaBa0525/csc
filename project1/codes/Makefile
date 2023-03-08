CXX := g++
CXXFLAGS := -std=c++17 -Wall -I include
DFLAG := -g

HIJACK = ipsec_hijack

SRC := $(wildcard src/*.cpp)
OBJ := $(patsubst src/%.cpp, objects/%.o, $(SRC))

.PHONY: all clean

all: objects $(HIJACK)

$(HIJACK): $(OBJ)
	$(CXX) $^ -o $@ $(CXXFLAGS) $(DFLAG)

objects/%.o: src/%.cpp
	$(CXX) $< -c -o $@ $(CXXFLAGS)

objects:
	mkdir -p $@

clean:
	-rm -rf objects
	-rm -f $(HIJACK)
