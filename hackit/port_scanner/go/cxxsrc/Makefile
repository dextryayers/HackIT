CXX = g++
CXXFLAGS = -std=c++17 -O3 -march=native -mtune=native -flto -fPIC \
           -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
           -Wno-unused-variable -Wno-sign-compare -Wno-missing-field-initializers \
           -Wno-implicit-fallthrough -Wno-builtin-macro-redefined
LDFLAGS = -shared -fPIC -lpthread -lm -Wl,--push-state,--no-as-needed -lssl -lcrypto -Wl,--pop-state

SRCS = $(wildcard *.cpp)
EXCLUDE = portstorm_cpp_dispatch.cpp deep_auditor.cpp service_audit.cpp surface_analyzer.cpp
SCANNER_SRCS = $(filter-out $(EXCLUDE), $(SRCS))
SCANNER_OBJS = $(SCANNER_SRCS:.cpp=.o)
DISPATCH_OBJ = portstorm_cpp_dispatch.o
ALL_OBJS = $(SCANNER_OBJS) $(DISPATCH_OBJ)
TARGET = ../libportstorm_cpp.so

.PHONY: all clean

all: $(TARGET)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) \
		-Dmain=$(subst .cpp,,$(notdir $<))_main \
		-c $< -o $@

portstorm_cpp_dispatch.o: portstorm_cpp_dispatch.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(ALL_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^
	@echo "[+] Built $(TARGET) with $(words $(SCANNER_SRCS)) scanner modules"

clean:
	rm -f *.o $(TARGET)

inventory:
	@echo "=== PortStorm C++ Engine Inventory ==="
	@echo "Scanner modules: $(words $(SCANNER_SRCS))"
	@for f in $(SCANNER_SRCS); do echo "  $$f"; done