# Makefile that uses uWSGI to build the plugin

all : prometheus_plugin.so

prometheus_plugin.so : prometheus_plugin.c
	uwsgi --build-plugin "$(<D)"

clean:
	rm -f prometheus_plugin.so
