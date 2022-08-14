TOPDIR=..
TARGET=$(TOPDIR)/xdp_count.o
SOURCE=xdp_count.c

all: $(TARGET)

$(TARGET): $(SOURCE) 
	clang -target bpf -Wall -O2 -c -Xclang -target-feature -Xclang +dwarfris -c $< -o $@
clean: 
	rm -rf $(TARGET)
