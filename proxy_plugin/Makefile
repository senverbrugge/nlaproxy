# Makefile for proxy-nlaproxy-plugin.so
#
# Build:    make
# Install:  sudo make install
#
# The plugin must be installed into FreeRDP's compiled-in plugin directory.
# The exact path and the accepted filename convention vary by distro:
#
#   FreeRDP >= 3.16 (Debian/Ubuntu, RHEL, current Fedora)
#     dir:      /usr/lib/<multiarch>/freerdp3/proxy/
#     filename: proxy-<name>-plugin.so   (no "lib" prefix)
#
#   FreeRDP >= 3.25 (Arch)
#     dir:      /usr/lib/freerdp/server/proxy/plugins/
#     filename: BOTH proxy-<name>-plugin.so and libproxy-<name>-plugin.so
#               are searched, so either works. Arch ships its own plugins with
#               the "lib" prefix but we standardise on the no-prefix name for
#               portability.
#
# The install target autodetects the dir; the filename we always use is
# `proxy-nlaproxy-plugin.so`, which is what every FreeRDP 3.x release we
# care about will look for.

CC      ?= cc
PKG_CONFIG ?= pkg-config
PKG     := freerdp-server-proxy3

# Verify the dev headers are present before any other target runs.
ifeq ($(shell $(PKG_CONFIG) --exists $(PKG) && echo ok),)
$(error "Missing pkg-config package '$(PKG)'. Install the FreeRDP 3 development files (e.g. 'freerdp' on Arch, 'freerdp3-dev' + 'freerdp3-proxy' on Debian/Ubuntu).")
endif

CFLAGS  ?= -O2 -g -Wall -Wextra -Wpedantic -fPIC \
           -D_FORTIFY_SOURCE=2 -fstack-protector-strong
# Silence deprecation warnings emitted by the FreeRDP/WinPR public headers
# themselves; they are noise for plugin authors and we don't touch the
# deprecated APIs.
CFLAGS  += -Wno-deprecated-declarations
LDFLAGS ?= -Wl,-z,relro,-z,now -Wl,--as-needed

PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PKG))
PKG_LIBS   := $(shell $(PKG_CONFIG) --libs $(PKG))

# Plugin install directory: FREERDP_PROXY_PLUGINDIR baked into FreeRDP at
# build time. The layout depends on the distro packaging.
#
# We autodetect by looking for a directory that already contains one of the
# stock demo plugins shipped by the freerdp*-proxy-modules / freerdp package.
# If nothing is found we fall back to the Debian multiarch layout because
# that's what Ubuntu/Debian users are most likely to be on when this needs
# to be discovered explicitly.
PLUGIN_DIR ?= $(shell \
    for d in /usr/lib/x86_64-linux-gnu/freerdp3/proxy \
             /usr/lib/aarch64-linux-gnu/freerdp3/proxy \
             /usr/lib64/freerdp3/proxy \
             /usr/lib/freerdp3/proxy \
             /usr/lib/freerdp/server/proxy/plugins \
             /usr/lib64/freerdp/server/proxy/plugins \
             /usr/lib/x86_64-linux-gnu/freerdp/server/proxy/plugins; do \
        for f in "$$d"/proxy-*-plugin.so "$$d"/libproxy-*-plugin.so; do \
            [ -e "$$f" ] && { echo "$$d"; exit 0; }; \
        done; \
    done; echo /usr/lib/x86_64-linux-gnu/freerdp3/proxy)

MODULE := proxy-nlaproxy-plugin.so
SRC    := nlaproxy_plugin.c

.PHONY: all clean install uninstall show-plugin-dir

all: $(MODULE)

$(MODULE): $(SRC)
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -shared -o $@ $(SRC) $(LDFLAGS) $(PKG_LIBS)

clean:
	rm -f $(MODULE) *.o libproxy-nlaproxy-plugin.so

# Diagnostic: print the plugin dir the install target would use.
show-plugin-dir:
	@echo "$(PLUGIN_DIR)"

install: $(MODULE)
	@if [ -z "$(PLUGIN_DIR)" ] || [ ! -d "$(PLUGIN_DIR)" ]; then \
	    echo "error: could not locate FreeRDP proxy plugin directory."; \
	    echo "       Install 'freerdp3-proxy-modules' (Debian/Ubuntu) or"; \
	    echo "       'freerdp' (Arch) first, or set PLUGIN_DIR explicitly:"; \
	    echo "           sudo make PLUGIN_DIR=/path/to/plugins install"; \
	    exit 1; \
	fi
	@echo "Installing $(MODULE) to $(PLUGIN_DIR)"
	install -d -m 0755 $(DESTDIR)$(PLUGIN_DIR)
	install -m 0755 -o root -g root $(MODULE) $(DESTDIR)$(PLUGIN_DIR)/$(MODULE)
	@echo
	@echo "Then in /etc/nlaproxy/proxy.ini set:"
	@echo "  [Plugins]"
	@echo "  Modules=nlaproxy"
	@echo "  Required=nlaproxy"

uninstall:
	rm -f $(DESTDIR)$(PLUGIN_DIR)/$(MODULE)
	rm -f $(DESTDIR)$(PLUGIN_DIR)/libproxy-nlaproxy-plugin.so
