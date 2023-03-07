CXX := g++
CXXFLAGS := -std=c++17 -Wall -I include
DFLAG := -g

HIJACK = ipsec_hijack

SRC := $(wildcard src/*.cpp)
OBJ := $(patsubst src/%.cpp, objects/%.o, $(SRC))

$(info $$OBJ is [$(OBJ)])

.PHONY: all clean

all: $(HIJACK)

$(HIJACK): $(OBJ)
	$(CXX) $^ -o $@ $(CXXFLAGS) $(DFLAG)

objects/%.o: objects src/%.cpp
	$(CXX) $^ -c -o $@ $(CXXFLAGS)

objects:
	mkdir objects

clean:
	-rm -rf objects
	-rm -f $(HIJACK)
