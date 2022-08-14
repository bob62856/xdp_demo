SUBDIRS := main bpf

all: $(SUBDIRS)
	@for dir in $(SUBDIRS); do \
		make -C $$dir; \
	done

clean: $(SUBDIRS)
	@for dir in $(SUBDIRS); do \
		make -C $$dir clean; \
	done
