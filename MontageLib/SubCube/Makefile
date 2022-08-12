.SUFFIXES:
.SUFFIXES: .c .o

CC     =	gcc
CFLAGS =	-g -O2 -I. -I.. -I../../lib/include -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -std=c99 -fPIC -Wall -fopenmp
LIBS   =	-fopenmp -L../../lib -lcoord -lwcs -lcfitsio -lm -lcurl -lcrypto

.c.o:
		$(CC) $(CFLAGS)  -c  $*.c

mSubCube:	mSubCube.o montageSubCube.o s3_driver.o
				$(CC) -o mSubCube mSubCube.o montageSubCube.o s3_driver.o ../util/debugCheck.o ../util/checkFile.o ../util/checkHdr.o ../util/checkWCS.o $(LIBS)

install:
		cp mSubCube ../../bin

clean:
		rm -f mSubCube *.o
