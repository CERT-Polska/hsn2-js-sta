
COMPONENT=js-analyzer
FULL_COMPONENT=hsn2-${COMPONENT}

all:	${FULL_COMPONENT}-package

clean:	${FULL_COMPONENT}-package-clean

${FULL_COMPONENT}-package:
	cd lib; make
	mvn clean install -U -Pbundle -Dmaven.test.skip
	mkdir -p build/${COMPONENT}
	tar xzf target/${FULL_COMPONENT}-1.0.0-SNAPSHOT.tar.gz -C build/${COMPONENT}

${FULL_COMPONENT}-package-clean:
	rm -rf build
	cd lib; make clean

build-local:
	mvn clean install -U -Pbundle
