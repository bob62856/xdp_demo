.PHONY: all clean

TARGET=xdp_pass.o

all: $(TARGET)

$(TARGET): xdp_pass.c
	clang -O2 -Wall -target bpf -c xdp_pass.c -o xdp_pass.o

clean: 
	rm $(TARGET)
  
