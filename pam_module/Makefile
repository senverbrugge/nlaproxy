# Makefile for pam_nlaproxy.so
#
# Build:
#   make
# Install (as root):
#   make install
# Uninstall:
#   make uninstall

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -Wpedantic -fPIC -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,--as-needed
LDLIBS  := -lpam

# Default install location: lib/security on most Linux distros.
# Adjust to /lib64/security on RHEL/Fedora or /lib/x86_64-linux-gnu/security on Debian
# if needed.
PAM_MODULE_DIR ?= $(shell \
    for d in /lib64/security \
             /lib/x86_64-linux-gnu/security \
             /usr/lib64/security \
             /usr/lib/x86_64-linux-gnu/security \
             /usr/lib/security \
             /lib/security; do \
        [ -d "$$d" ] && { echo "$$d"; exit 0; }; \
    done; echo /usr/lib/security)

MODULE := pam_nlaproxy.so
SRC    := pam_nlaproxy.c

.PHONY: all clean install uninstall

all: $(MODULE)

$(MODULE): $(SRC)
	$(CC) $(CFLAGS) -shared -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(MODULE) *.o

install: $(MODULE)
	@echo "Installing $(MODULE) to $(PAM_MODULE_DIR)"
	install -d -m 0755 $(DESTDIR)$(PAM_MODULE_DIR)
	install -m 0755 -o root -g root $(MODULE) $(DESTDIR)$(PAM_MODULE_DIR)/$(MODULE)
	@echo
	@echo "Now add the following two lines to /etc/pam.d/sshd, both placed"
	@echo "AFTER the real authenticator (e.g. @include common-auth on Debian/"
	@echo "Ubuntu, or 'auth substack password-auth' on RHEL/Fedora/Arch):"
	@echo
	@echo "  auth       optional    pam_nlaproxy.so"
	@echo "  session    optional    pam_nlaproxy.so"
	@echo

uninstall:
	rm -f $(DESTDIR)$(PAM_MODULE_DIR)/$(MODULE)
