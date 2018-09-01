
include ../common.mak

BINS = modbus 

SRCS := $(wildcard ./*.c)
OBJS := $(subst .c,.o,$(SRCS))
CFLAGS += -I../libemqtt/include -I../sqlite/

all: ${BINS}

${BINS}: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) -L$(TOP)/nvram -lnvram -L$(TOP)/shared -lshared -lm -lpthread -L$(TOP)/libemqtt -lemqtt -L$(TOP)/sqlite/.libs -lsqlite3 -lpthread
	#${LD} $(LDFLAGS) ${OBJS} ${LDADD} -o ${BINS} 

$(OBJS):%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@ -I$(SRCBASE) -I$(SRCBASE)/include -I$(TOP)/shared
clean:
	rm -f *.[oa] *.elf *~ core ${BINS} *.gdb
install: all
	install -D ${BINS} $(INSTALLDIR)/sbin/${BINS}
	$(STRIP) ${INSTALLDIR}/sbin/${BINS}
	chmod 0500 ${INSTALLDIR}/sbin/${BINS}


