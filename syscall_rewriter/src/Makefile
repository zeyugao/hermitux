PREFIX=/home/elsa/dyninst

CXX=g++
CXXFLAGS=-I${PREFIX}/include/
LDFLAGS=-L${PREFIX}/lib -lpatchAPI -lsymtabAPI -linstructionAPI \
		-ldyninstAPI -lparseAPI \
		-lpthread
SRC=$(shell ls *.cpp)
OBJ=$(SRC:.cpp=.o)
PROG=rewrite_syscalls

all: $(PROG)

$(PROG): $(OBJ)
	LD_LIBRARY_PATH=${PREFIX}/lib $(CXX) $^ -o $(PROG) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

clean:
	rm -rf *.o $(PROG)