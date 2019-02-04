
build:
	cargo build --release

debbuild:
	@for dir in webnis-bind webnis-nss webnis-pam webnis-server; do \
		if [ -e $$dir/debian ]; then \
			( cd $$dir && dpkg-buildpackage -rfakeroot ); \
		fi; \
	done

debbuild-unsigned:
	@for dir in webnis-bind webnis-nss webnis-pam webnis-server; do \
		if [ -e $$dir/debian ]; then \
			( cd $$dir && dpkg-buildpackage -rfakeroot -us -uc ); \
		fi; \
	done

clean:
	rm -f *.deb *.dsc *.tar.xz *.buildinfo *.changes
	@for dir in webnis-bind webnis-nss webnis-pam webnis-server; do \
		if [ -e $$dir/debian ]; then \
			( cd $$dir && dpkg-buildpackage -T clean ); \
		fi; \
	done

realclean: clean
	rm -rf target/*

install: build
	sudo install -o root -g root -m 644 target/release/libnss_webnis.so /lib/x86_64-linux-gnu/libnss_webnis.so.2
	sudo install -o root -g root -m 644 target/release/libpam_webnis.so /lib/security/pam_webnis.so
