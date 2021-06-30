# uwsgi_prometheus_plugin
[![Build](https://github.com/skyhisi/uwsgi_prometheus_plugin/actions/workflows/build.yml/badge.svg)](https://github.com/skyhisi/uwsgi_prometheus_plugin/actions/workflows/build.yml)
[![License: GPL 2](https://img.shields.io/github/license/skyhisi/uwsgi_prometheus_plugin?color=green)](https://github.com/skyhisi/uwsgi_prometheus_plugin/blob/main/LICENSE)

Prometheus exporter for uWSGI as a plugin

This plugin runs a Prometheus exporter inside the uWSGI process which avoids
the need to configure and manage a separate process.

## Building
The plugin can be built using the built-in uWSGI plugin building option, for
convenience the provided Makefile will do this.

```
git clone https://github.com/skyhisi/uwsgi_prometheus_plugin.git
cd uwsgi_prometheus_plugin
make
```

This will generate the plugin file `prometheus_plugin.so`

Depending on your OS, some extra packages may need to be installed:

 * Debian
   ```
   apt install uwsgi build-essential libcap-dev libpcre3-dev libssl-dev
   ```
 * Fedora
   ```
   dnf groupinstall 'C Development Tools and Libraries'
   dnf install uwsgi libcap-devel pcre-devel openssl-devel
   ```

## uWSGI Configuration
Load the plugin by adding it to the configuration file, for example as an
ini file:
```
[uwsgi]
plugins=http,python3,./prometheus_plugin.so
...
```

By default, for compatibility with other uWSGI exporters, the plugin will
listen on TCP port 9117.

This can be changed with the `prometheus-listen` option, for example in an
ini file:
```
prometheus-listen=127.0.0.1:8081
```

## Prometheus Configuration
Add a new target to the `prometheus.yml` file, for example:
```
scrape_configs:
  - job_name: uwsgi
    static_configs:
      - targets: ['127.0.0.1:9117']
```

## Example Prometheus Queries
Some example queries:
 * Request rate across all workers:
   ```
   sum(rate(uwsgi_worker_requests[5m])) without (id)
   ```
 * Count of busy workers:
   ```
   sum (uwsgi_worker_busy) without (id)
   ```

