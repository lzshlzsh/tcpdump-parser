.PHONY: all clean

src := $(wildcard *.cpp)
obj := $(patsubst %.cpp,%.o,${src})
target := $(patsubst %.cpp,%,${src})
header := $(wildcard *.h)

CXXFLAGS := -g

all: ${target}

${target}: %: %.o
	${CXX} ${CXXFLAGS} -o $@ ${LDFLAGS} ${LDLIBS} $^

${obj}: %.o: %.cpp ${header}

clean:
	${RM} ${obj} ${target}
