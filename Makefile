OPTFLAGS = -march=native -mtune=native -O2
CXXFLAGS += -g -Wall -Wextra -Wno-unused-parameter -std=c++11 -fPIC -Wno-unused-variable
#CXXFLAGS += -I $(DEPINST)/include -I $(DEPINST)/include/libsnark -DUSE_ASM -DCURVE_ALT_BN128 -DDEBUG
CXXFLAGS += -I $(DEPINST)/include -I $(DEPINST)/include/libsnark -DUSE_ASM -DCURVE_ALT_BN128
LDFLAGS += -flto

DEPSRC=depsrc
DEPINST=depinst

LDLIBS += -L $(DEPINST)/lib -Wl,-rpath $(DEPINST)/lib -L . -lsnark -lgmpxx -lgmp
LDLIBS += -lboost_system

all:
	$(CXX) -o main.o src/main.cpp -c $(CXXFLAGS)
	$(CXX) -o main main.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) main.o main
