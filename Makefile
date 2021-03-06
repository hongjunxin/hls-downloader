TARGET = obj/dhls
#CFLAG = -g -fno-stack-protector -DUSE_CURL
CFLAG = -g -fno-stack-protector
LDFLAG = -lssl -lcrypto -lcurl
CC = gcc

OBJ = obj/downloader.o \
	  obj/http.o \
	  obj/utility.o \
	  obj/epoll.o \
	  obj/mcurl.o

HEADER = log.h

all: prepare $(TARGET)

prepare:
	@if [ ! -e obj ]; then \
		mkdir obj; \
	fi

$(TARGET) : $(OBJ)
	$(CC) $(OBJ) $(LDFLAG) -o $@

obj/downloader.o : downloader.c $(HEADER)
	$(CC) -c $(CFLAG) $< -o $@

obj/http.o : http.c http.h $(HEADER)
	$(CC) -c $(CFLAG) $< -o $@

obj/utility.o : utility.c utility.h $(HEADER)
	$(CC) -c $(CFLAG) $< -o $@

obj/epoll.o : epoll.c epoll.h $(HEADER)
	$(CC) -c $(CFLAG) $< -o $@

obj/mcurl.o : mcurl.c mcurl.h $(HEADER)
	$(CC) -c $(CFLAG) $< -o $@

clean:
	rm -rf $(OBJ) $(TARGET)
