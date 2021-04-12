all:
	mkdir -p bin
	mkdir -p lib/include
	test ! -d lib/src    || (cd lib/src    && $(MAKE))
	test ! -d Montage    || (cd Montage    && $(MAKE) && $(MAKE) install)
	test ! -d util       || (cd util       && $(MAKE))
	test ! -d grid       || (cd grid       && $(MAKE))
	test ! -d MontageLib || (cd MontageLib && $(MAKE))
	test ! -d ancillary  || (cd ancillary  && $(MAKE) && $(MAKE) install)
	test ! -d HiPS       || (cd HiPS       && $(MAKE))

clean:
	mkdir -p bin
	mkdir -p lib/include
	rm -rf bin/*
	test ! -d lib/src          || (cd lib/src    && $(MAKE) clean)
	test ! -e Montage/Makefile || (cd Montage    && $(MAKE) clean)
	test ! -d util             || (cd util       && $(MAKE) clean)
	test ! -d grid             || (cd grid       && $(MAKE) clean)
	test ! -d MontageLib       || (cd MontageLib && $(MAKE) clean)
	test ! -d ancillary        || (cd ancillary  && $(MAKE) clean)
	test ! -d HiPS             || (cd HiPS       && $(MAKE) clean)
