TOPDIR=..
TARGET=$(TOPDIR)/get_count
SOURCE=get_count.c

LIBDIR=include

# -lelf default to find ./usr/lib/x86_64-linux-gnu/libelf.so 
# -lbpf default to find ./lib/x86_64-linux-gnu/libbpf.so
$(TARGET) : $(SOURCE)
	$(CC) -Wall $< -o $@ -L$(LIBDIR) -lbpf -lelf


clean:
	rm -rf $(TARGET)
