.PHONY: all clean

src := $(wildcard *.cpp)
obj := $(patsubst %.cpp,%.o,${src})
target := $(patsubst %.cpp,%,${src})

CXXFLAGS := -g

all: ${target}

${target}: %: %.o
	${CXX} ${CXXFLAGS} -o $@ ${LDFLAGS} ${LDLIBS} $^

clean:
	${RM} ${obj} ${target}
