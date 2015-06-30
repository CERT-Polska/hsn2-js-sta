#
# This Makefile is responsoble for build debian package.
# 4 variables must be provided:
#   HSN2_VER=2.0
#   BUILD_NUMBER=999
#   DEBIAN_DIST=(experimental|2.0)

DEBIAN_DIST=experimental
HSN2_COMPONENT=js-sta

all:    hsn2-js-sta-i386  hsn2-js-sta-amd64

clean:  hsn2-static-analyzer-clean

PKGi386=hsn2-$(HSN2_COMPONENT)_$(HSN2_VER)-$(BUILD_NUMBER)_i386
hsn2-js-sta-i386: hsn2-js-sta-clean
		mkdir -p $(PKGi386)/DEBIAN
		mkdir -p $(PKGi386)/etc/hsn2/
		mkdir -p $(PKGi386)/etc/init.d/
		mkdir -p $(PKGi386)/opt/hsn2/$(HSN2_COMPONENT)
		mkdir -p $(PKGi386)/var/log/hsn2
		tar -zxf ../target/hsn2-js-analyzer-*.tar.gz -C $(PKGi386)/opt/hsn2/$(HSN2_COMPONENT)
#ngrams lib MUST be built already!!!
		cp libngrams.so $(PKGi386)/opt/hsn2/$(HSN2_COMPONENT)/lib/
#copy WEKA ARFF file
		cp ../out4.arff $(PKGi386)/opt/hsn2/$(HSN2_COMPONENT)/lib/weka.arff
		cp ../whitelist.ssdeep $(PKGi386)/opt/hsn2/$(HSN2_COMPONENT)/lib/whitelist.ssdeep
		cp js-static-analyzer.initd $(PKGi386)/etc/init.d/hsn2-$(HSN2_COMPONENT)
		cp control $(PKGi386)/DEBIAN
		sed -i "s/{VER}/${HSN2_VER}-${BUILD_NUMBER}/" $(PKGi386)/DEBIAN/control
		sed -i "s/{DEBIAN_DIST}/${DEBIAN_DIST}/" $(PKGi386)/DEBIAN/control
		fakeroot dpkg -b $(PKGi386)

PKGamd64=hsn2-$(HSN2_COMPONENT)_$(HSN2_VER)-$(BUILD_NUMBER)_amd64
hsn2-js-sta-amd64: hsn2-js-sta-clean
		mkdir -p $(PKGamd64)/DEBIAN
		mkdir -p $(PKGamd64)/etc/hsn2/
		mkdir -p $(PKGamd64)/etc/init.d/
		mkdir -p $(PKGamd64)/opt/hsn2/$(HSN2_COMPONENT)
		mkdir -p $(PKGamd64)/var/log/hsn2
		tar -zxf ../target/hsn2-js-analyzer-*.tar.gz -C $(PKGamd64)/opt/hsn2/$(HSN2_COMPONENT)
#pre-build amd64 lib
		cp libngrams.so $(PKGamd64)/opt/hsn2/$(HSN2_COMPONENT)/lib/
#copy WEKA ARFF file
		cp ../out4.arff $(PKGamd64)/opt/hsn2/$(HSN2_COMPONENT)/lib/weka.arff
		cp ../whitelist.ssdeep $(PKGamd64)/opt/hsn2/$(HSN2_COMPONENT)/lib/whitelist.ssdeep
		cp js-static-analyzer.initd $(PKGamd64)/etc/init.d/hsn2-$(HSN2_COMPONENT)
		cp control $(PKGamd64)/DEBIAN
		sed -i "s/{VER}/${HSN2_VER}-${BUILD_NUMBER}/" $(PKGamd64)/DEBIAN/control
		sed -i "s/{DEBIAN_DIST}/${DEBIAN_DIST}/" $(PKGamd64)/DEBIAN/control
		sed -i "s/i386/amd64/" $(PKGamd64)/DEBIAN/control
		fakeroot dpkg -b $(PKGamd64)

hsn2-js-sta-clean:
		rm -rf hsn2-js-sta_*
