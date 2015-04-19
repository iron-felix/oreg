
CPPFLAGS=-I/usr/include/iceweasel-31 -DXP_UNIX -Wall -fno-gnu-tm -std=c++11

target=npifcfree.so

.PHONY: install clean

%.o: %.cpp
	$(CXX) $(CPPFLAGS) -c -fPIC -O3 $<

$(target): ifcfree.o
	$(CXX) $(CPPFLAGS) -o $@ $< -shared

clean:
	-$(RM) $(target) *.o

install: $(target)
	install -D $(target) ~/.mozilla/plugins/$(target)

