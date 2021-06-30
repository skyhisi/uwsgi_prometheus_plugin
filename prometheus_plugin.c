/* Prometheus exporter for uWSGI as a plugin.
 * Copyright (C) 2021 Silas Parker
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <uwsgi.h>
#include <stdarg.h>

#define NAME "prometheus-exporter"
#define LOG_PREFIX "[" NAME "] "
#define DATA_PAGES (16)
#define MAX_EVENTS (2)


static void prometheus_listen_thread(struct uwsgi_thread*);
static void prometheus_stat_printf(const char* format, ...) __attribute__ ((format(printf, 1, 2)));
static void prometheus_stats_pusher(struct uwsgi_stats_pusher_instance *uspi, time_t now, char *json, size_t json_len);

extern struct uwsgi_server uwsgi;

static struct uwsgi_prometheus
{
  struct uwsgi_stats_pusher* pusher;
  struct uwsgi_lock_item* data_lock;
  char* data_buffer;
  size_t data_size;
  size_t data_used;
  uint64_t data_time;
  struct uwsgi_thread* thread;
  int freq;
  char* listen_addr;
} u_prom = {
  NULL,
  NULL,
  NULL,
  0,
  0,
  0,
  NULL,
  5,
  NULL
};

static struct uwsgi_option uwsgi_prometheus_options[] =
{
  {"prometheus-freq", required_argument, 0, "stats update frequency (default: 5)", uwsgi_opt_set_int, &u_prom.freq, 0},
  {"prometheus-listen", required_argument, 0, "listen address", uwsgi_opt_set_str, &u_prom.listen_addr, 0},
  {NULL, 0, 0, NULL, NULL, NULL, 0},
};

// Early initialisation after plugin load
static void prometheus_on_load(void)
{
  //uwsgi_log(LOG_PREFIX "On Load (pid: %d)\n", getpid());
  u_prom.pusher = uwsgi_register_stats_pusher(NAME, &prometheus_stats_pusher);
  u_prom.pusher->raw = 1;
  u_prom.listen_addr = strdup(":9117"); // Leaks 6 bytes when overridden
}

// Initialisation after options parsed
static int prometheus_init()
{
  //uwsgi_log(LOG_PREFIX "Init (pid: %d)\n", getpid());

  u_prom.data_lock = uwsgi_rwlock_init(NAME);
  u_prom.data_size = DATA_PAGES * uwsgi.page_size;
  u_prom.data_buffer = uwsgi_calloc(u_prom.data_size);

  struct uwsgi_stats_pusher_instance *uspi = uwsgi_stats_pusher_add(u_prom.pusher, NULL);
  uspi->raw = 1;
  uspi->freq = u_prom.freq;

  u_prom.thread = uwsgi_thread_new(&prometheus_listen_thread);
  return 0;
}

// Append a stat to the buffer
static void prometheus_stat_vprintf(const char* format, va_list ap)
{
  char* buf = u_prom.data_buffer + u_prom.data_used;
  size_t maxlen = u_prom.data_size - u_prom.data_used;
  int rc = vsnprintf(buf, maxlen, format, ap);
  if (rc < 0)
  {
    memset(buf, 0, maxlen);
    uwsgi_log(LOG_PREFIX "failed to format stat!!!\n");
    return;
  }
  if (rc >= (int)maxlen)
  {
    memset(buf, 0, maxlen);
    uwsgi_log(LOG_PREFIX "data buffer too small!!!\n");
    return;
  }
  u_prom.data_used += rc;
}

// Append a stat to the buffer
static void prometheus_stat_printf(const char* format, ...)
{
  va_list ap;
  va_start(ap, format);
  prometheus_stat_vprintf(format, ap);
  va_end(ap);
}

// Called by the stats pusher framework, this runs in the master and writes to the shared data block
static void prometheus_stats_pusher(struct uwsgi_stats_pusher_instance *uspi, time_t now, char *json, size_t json_len)
{
  struct timeval tv;

  //uwsgi_log(LOG_PREFIX "Stats Pusher (pid: %d)\n", getpid());

  // Setup buffer
  uwsgi_wlock(u_prom.data_lock);
  u_prom.data_used = 0;
  //memset(u_prom.data_buffer, 0, u_prom.data_size); // TODO: Remove - Only for debug
	gettimeofday(&tv, NULL);
	u_prom.data_time = ((uint64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);


#ifdef __linux__
  prometheus_stat_printf("uwgsi_listen_queue %ju %ju\n", uwsgi.shared->backlog, u_prom.data_time);
  prometheus_stat_printf("uwgsi_listen_queue_errors %ju %ju\n", uwsgi.shared->backlog_errors, u_prom.data_time);
#endif

  int signal_queue = 0;
  if (ioctl(uwsgi.shared->worker_signal_pipe[1], FIONREAD, &signal_queue)) {
    uwsgi_error(LOG_PREFIX "prometheus_stats_pusher() -> ioctl()\n");
  }
  prometheus_stat_printf("uwgsi_signal_queue %d %ju\n", signal_queue, u_prom.data_time);
  prometheus_stat_printf("uwsgi_load %ju %ju\n", uwsgi.shared->load, u_prom.data_time);

  for (struct uwsgi_daemon *ud = uwsgi.daemons; ud; ud = ud->next)
  {
    char *cmd = uwsgi_malloc((strlen(ud->command)*2)+1);
    escape_json(ud->command, strlen(ud->command), cmd);
    prometheus_stat_printf("uwsgi_daemon_status{cmd=\"%s\"} %d %ju\n", cmd, ud->status, u_prom.data_time);
    prometheus_stat_printf("uwsgi_daemon_respawns{cmd=\"%s\"} %ju %ju\n", cmd, ud->respawns, u_prom.data_time);
    free(cmd);
  }

  for (struct uwsgi_lock_item *uli = uwsgi.registered_locks; uli; uli = uli->next)
  {
    prometheus_stat_printf("uwsgi_lock_pid{id=\"%s\"} %d %ju\n", uli->id, uli->pid, u_prom.data_time);
  }

  for (struct uwsgi_cache *uc = uwsgi.caches; uc; uc = uc->next)
  {
    const char* name = uc->name ? uc->name : "default";
    prometheus_stat_printf("uwsgi_cache_hashsize{name=\"%s\"} %u %ju\n", name, uc->hashsize, u_prom.data_time);
    prometheus_stat_printf("uwsgi_cache_keysize{name=\"%s\"} %ju %ju\n", name, uc->keysize, u_prom.data_time);
    prometheus_stat_printf("uwsgi_cache_max_items{name=\"%s\"} %ju %ju\n", name, uc->max_items, u_prom.data_time);
    prometheus_stat_printf("uwsgi_cache_blocks{name=\"%s\"} %ju %ju\n", name, uc->blocks, u_prom.data_time);
    prometheus_stat_printf("uwsgi_cache_blocksize{name=\"%s\"} %ju %ju\n", name, uc->blocksize, u_prom.data_time);
    prometheus_stat_printf("uwsgi_cache_items{name=\"%s\"} %ju %ju\n", name, uc->n_items, u_prom.data_time);
    prometheus_stat_printf("uwsgi_cache_hits{name=\"%s\"} %ju %ju\n", name, uc->hits, u_prom.data_time);
    prometheus_stat_printf("uwsgi_cache_miss{name=\"%s\"} %ju %ju\n", name, uc->miss, u_prom.data_time);
    prometheus_stat_printf("uwsgi_cache_full{name=\"%s\"} %ju %ju\n", name, uc->full, u_prom.data_time);
    prometheus_stat_printf("uwsgi_cache_last_modified_at{name=\"%s\"} %lu %ju\n", name, uc->last_modified_at, u_prom.data_time);
  }

  for (struct uwsgi_metric *um = uwsgi.metrics; um; um = um->next)
  {
    uwsgi_rlock(uwsgi.metrics_lock);
    prometheus_stat_printf("uwsgi_metric{name=\"%s\"} %lld %ju\n", um->name, (long long)(*um->value), u_prom.data_time);
    uwsgi_rwunlock(uwsgi.metrics_lock);
    if (um->reset_after_push)
    {
      uwsgi_wlock(uwsgi.metrics_lock);
      *um->value = um->initial_value;
      uwsgi_rwunlock(uwsgi.metrics_lock);
    }
  }

  for (struct uwsgi_socket* us = uwsgi.sockets; us; us = us->next)
  {
    const char* proto = us->proto_name ? us->proto_name : "uwsgi";
    prometheus_stat_printf("uwsgi_socket_queue{name=\"%s\",proto=\"%s\"} %ju %ju\n", us->name, proto, us->queue, u_prom.data_time);
    prometheus_stat_printf("uwsgi_socket_max_queue{name=\"%s\",proto=\"%s\"} %ju %ju\n", us->name, proto, us->max_queue, u_prom.data_time);
  }

  for (int i = 0; i < uwsgi.numproc; i++)
  {
    struct uwsgi_worker* worker = &uwsgi.workers[i + 1];
    prometheus_stat_printf("uwsgi_worker_accepting{id=\"%d\"} %d %ju\n", worker->id, worker->accepting, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_requests{id=\"%d\"} %ju %ju\n", worker->id, worker->requests, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_delta_requests{id=\"%d\"} %ju %ju\n", worker->id, worker->delta_requests, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_failed_requests{id=\"%d\"} %ju %ju\n", worker->id, worker->failed_requests, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_exceptions{id=\"%d\"} %ju %ju\n", worker->id, uwsgi_worker_exceptions(i+1), u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_harakiri_count{id=\"%d\"} %ju %ju\n", worker->id, worker->harakiri_count, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_signals{id=\"%d\"} %ju %ju\n", worker->id, worker->signals, u_prom.data_time);
    if (ioctl(worker->signal_pipe[1], FIONREAD, &signal_queue))
    {
      uwsgi_error(LOG_PREFIX "prometheus_stats_pusher() -> ioctl()\n");
    }
    prometheus_stat_printf("uwsgi_worker_signal_queue{id=\"%d\"} %d %ju\n", worker->id, signal_queue, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_cheaped{id=\"%d\"} %d %ju\n", worker->id, worker->cheaped, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_suspended{id=\"%d\"} %d %ju\n", worker->id, worker->suspended, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_sig{id=\"%d\"} %d %ju\n", worker->id, worker->sig ? worker->signum : 0, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_busy{id=\"%d\"} %d %ju\n", worker->id, uwsgi_worker_is_busy(i+1), u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_rss{id=\"%d\"} %ju %ju\n", worker->id, worker->rss_size, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_vsz{id=\"%d\"} %ju %ju\n", worker->id, worker->vsz_size, u_prom.data_time);
    //prometheus_stat_printf("uwsgi_worker_uss{id=\"%d\"} %ju %ju\n", worker->id, worker->uss_size, u_prom.data_time);
    //prometheus_stat_printf("uwsgi_worker_sss{id=\"%d\"} %ju %ju\n", worker->id, worker->pss_size, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_last_spawn{id=\"%d\"} %ld %ju\n", worker->id, worker->last_spawn, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_respawn_count{id=\"%d\"} %ju %ju\n", worker->id, worker->respawn_count, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_tx{id=\"%d\"} %ju %ju\n", worker->id, worker->tx, u_prom.data_time);
    prometheus_stat_printf("uwsgi_worker_avg_rt{id=\"%d\"} %ju %ju\n", worker->id, worker->avg_response_time, u_prom.data_time);

    for (int j = 0; j < uwsgi.workers[i + 1].apps_cnt; j++)
    {
      struct uwsgi_app *ua = &worker->apps[j];
      char* mnt = uwsgi_malloc((ua->mountpoint_len * 2) + 1);
      escape_json(ua->mountpoint, ua->mountpoint_len, mnt);
      prometheus_stat_printf("uwsgi_worker_app_requests{worker=\"%d\",id=\"%d\",mountpoint=\"%s\",modifier1=\"%d\"} %ju %ju\n", worker->id, j, mnt, ua->modifier1, ua->requests, u_prom.data_time);
      prometheus_stat_printf("uwsgi_worker_app_exceptions{worker=\"%d\",id=\"%d\",mountpoint=\"%s\",modifier1=\"%d\"} %ju %ju\n", worker->id, j, mnt, ua->modifier1, ua->exceptions, u_prom.data_time);
      free(mnt);
    }

    for (int j = 0; j < uwsgi.cores; j++)
    {
      struct uwsgi_core *uc = &worker->cores[j];
      prometheus_stat_printf("uwsgi_worker_core_requests{worker=\"%d\",id=\"%d\"} %ju %ju\n", worker->id, j, uc->requests, u_prom.data_time);
      prometheus_stat_printf("uwsgi_worker_core_static_requests{worker=\"%d\",id=\"%d\"} %ju %ju\n", worker->id, j, uc->static_requests, u_prom.data_time);
      prometheus_stat_printf("uwsgi_worker_core_routed_requests{worker=\"%d\",id=\"%d\"} %ju %ju\n", worker->id, j, uc->routed_requests, u_prom.data_time);
      prometheus_stat_printf("uwsgi_worker_core_offloaded_requests{worker=\"%d\",id=\"%d\"} %ju %ju\n", worker->id, j, uc->offloaded_requests, u_prom.data_time);
      prometheus_stat_printf("uwsgi_worker_core_write_errors{worker=\"%d\",id=\"%d\"} %ju %ju\n", worker->id, j, uc->write_errors, u_prom.data_time);
      prometheus_stat_printf("uwsgi_worker_core_read_errors{worker=\"%d\",id=\"%d\"} %ju %ju\n", worker->id, j, uc->read_errors, u_prom.data_time);
    }
  }

  for (struct uwsgi_spooler *uspool = uwsgi.spoolers; uspool; uspool = uspool->next)
  {
    char* dir = uwsgi_malloc((strlen(uspool->dir) * 2) + 1);
    escape_json(uspool->dir, strlen(uspool->dir), dir);
    prometheus_stat_printf("uwsgi_spooler_tasks{pid=\"%d\",dir=\"%s\"} %ju %ju\n", uspool->pid, dir, uspool->tasks, u_prom.data_time);
    prometheus_stat_printf("uwsgi_spooler_respawns{pid=\"%d\",dir=\"%s\"} %ju %ju\n", uspool->pid, dir, uspool->respawned, u_prom.data_time);
    free(dir);
  }

  uwsgi_rwunlock(u_prom.data_lock);
}

// Send the stats HTTP response
static void prometheus_send_http(int fd)
{
  static const char initial_reply[] =
    "HTTP/1.0 200 OK\r\n"
    "Connection: close\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Content-Type: text/plain; version=0.0.4\r\n";

  char line[64] = {0};
  int len;
  size_t ub_size;
  struct uwsgi_buffer *ub;

  uwsgi_rlock(u_prom.data_lock);

  ub_size = uwsgi.page_size * (2 + (u_prom.data_used / uwsgi.page_size));
  ub = uwsgi_buffer_new(ub_size);

  if (uwsgi_buffer_append(ub, (char*)initial_reply, sizeof(initial_reply) - 1))
    goto unlock_error;

  len = snprintf(line, sizeof(line), "Content-Length: %zu\r\n\r\n", u_prom.data_used);
  if (uwsgi_buffer_append(ub, line, len))
    goto unlock_error;

  if (uwsgi_buffer_append(ub, u_prom.data_buffer, u_prom.data_used))
    goto unlock_error;

  uwsgi_rwunlock(u_prom.data_lock);

  if (uwsgi_buffer_send(ub, fd))
    goto error;

  uwsgi_buffer_destroy(ub);
  return;

unlock_error:
  uwsgi_rwunlock(u_prom.data_lock);
error:
  if (ub)
    uwsgi_buffer_destroy(ub);
  uwsgi_log(LOG_PREFIX "Failed to send data response\n");
}

// Send a HTTP 400 response
static void prometheus_send_http_400(int fd)
{
  static const char msg[] =
    "HTTP/1.0 400 Bad Request\r\n"
    "Connection: close\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 17\r\n"
    "\r\n"
    "400 Bad Request\r\n";
  if (uwsgi_write_nb(fd, (char*)msg, sizeof(msg) - 1, uwsgi.socket_timeout))
    uwsgi_log(LOG_PREFIX "Failed to send 400 response\n");
}

// Send a HTTP 404 response
static void prometheus_send_http_404(int fd)
{
  static const char msg[] =
    "HTTP/1.0 404 Not Found\r\n"
    "Connection: close\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "404 Not Found\r\n";
  if (uwsgi_write_nb(fd, (char*)msg, sizeof(msg) - 1, uwsgi.socket_timeout))
    uwsgi_log(LOG_PREFIX "Failed to send 404 response\n");
}

// Send a HTTP 405 response
static void prometheus_send_http_405(int fd)
{
  static const char msg[] =
    "HTTP/1.0 405 Method Not Allowed\r\n"
    "Connection: close\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 24\r\n"
    "Allow: GET\r\n"
    "\r\n"
    "405 Method Not Allowed\r\n";
  if (uwsgi_write_nb(fd, (char*)msg, sizeof(msg) - 1, uwsgi.socket_timeout))
    uwsgi_log(LOG_PREFIX "Failed to send 405 response\n");
}

// Send a index page
static void prometheus_send_http_index(int fd)
{
  static const char msg[] =
    "HTTP/1.0 200 OK\r\n"
    "Connection: close\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 130\r\n"
    "\r\n"
    "<html><head><title>uWSGI Exporter</title></head>"
    "<body><h1>uWSGI Exporter</h1>"
    "<p><a href='/metrics'>Metrics</a></p>"
    "</body></html>\r\n";
  if (uwsgi_write_nb(fd, (char*)msg, sizeof(msg) - 1, uwsgi.socket_timeout))
    uwsgi_log(LOG_PREFIX "Failed to send index response\n");
}

// Handle the client connection
static void prometheus_handle_client(int client_fd)
{
  char buf[1024] = {0};

  int rc = uwsgi_waitfd(client_fd, uwsgi.socket_timeout);
  if (rc < 0)
  {
    uwsgi_log(LOG_PREFIX "failed to poll client socket\n");
    return;
  }
  
  if (rc && (read(client_fd, buf, sizeof(buf)-1) < 0))
  {
    uwsgi_log(LOG_PREFIX "failed to read socket\n");
    return;
  }

  char* newline = strstr(buf, "\r\n");
  if (!newline)
  {
    uwsgi_log(LOG_PREFIX "HTTP parse failed to find line\n");
    prometheus_send_http_400(client_fd);
    return;
  }
  *newline = '\0';
  char *method, *path, *protocol;
  size_t method_len, path_len, protocol_len;
  if (!uwsgi_split3(buf, newline - buf, ' ', &method, &method_len, &path, &path_len, &protocol, &protocol_len))
  {
    uwsgi_log(LOG_PREFIX "HTTP parse failed to split\n");
    prometheus_send_http_400(client_fd);
    return;
  }
  //uwsgi_log(LOG_PREFIX "Parsed: \"%.*s\" \"%.*s\" \"%.*s\"\n", method_len, method, path_len, path, protocol_len, protocol);
  if (!uwsgi_strncmp("HTTP/1", 6, protocol, protocol_len))
  {
    uwsgi_log(LOG_PREFIX "Unknown protocol\n");
    prometheus_send_http_400(client_fd);
    return;
  }
  if (uwsgi_strncmp(method, method_len, "GET", 3))
  {
    prometheus_send_http_405(client_fd);
    return;
  }

  if (!uwsgi_strncmp(path, path_len, "/metrics", 8))
  {
    prometheus_send_http(client_fd);
  }
  else if (!uwsgi_strncmp(path, path_len, "/", 1))
  {
    prometheus_send_http_index(client_fd);
  }
  else
  {
    prometheus_send_http_404(client_fd);
  }
}


// Prometheus exporter endpoint thread
static void prometheus_listen_thread(struct uwsgi_thread* ut)
{
  void *events = event_queue_alloc(MAX_EVENTS);
  char buf[256];
  struct sockaddr_un client_src;
  socklen_t client_src_len;
  int server_fd;
  int run = 1;

  // Open socket
  char *tcp_port = strrchr(u_prom.listen_addr, ':');
  if (tcp_port)
  {
    server_fd = bind_to_tcp(u_prom.listen_addr, uwsgi.listen_queue, tcp_port);
  }
  else
  {
    server_fd = bind_to_unix(u_prom.listen_addr, uwsgi.listen_queue, uwsgi.chmod_socket, uwsgi.abstract_socket);
  }
  if (server_fd < 0)
  {
    uwsgi_log(LOG_PREFIX "Failed to open socket\n");
    close(u_prom.thread->pipe[1]);
    return;
  }

  // ut->pipe[1] is already added by the uwsgi_thread_run func
  event_queue_add_fd_read(ut->queue, server_fd);

  while (run)
  {
    int nevents = event_queue_wait_multi(ut->queue, 60, events, MAX_EVENTS);
    if (nevents < 0)
    {
      if (errno == EINTR)
        continue;
      uwsgi_log(LOG_PREFIX "Queue wait failed, stopping thread\n");
      break;
    }
    for (int i = 0; i < nevents; ++i)
    {
      int fd = event_queue_interesting_fd(events, 0);
      if (fd == ut->pipe[1])
      {
        ssize_t len = read(fd, buf, sizeof(buf));
        if (len <= 0)
        {
          uwsgi_log(LOG_PREFIX "Master connection closed, stopping thread\n");
          run = 0;
          break;
        }
        else if (!uwsgi_strncmp(buf, len, "STOP", 4))
        {
          //uwsgi_log(LOG_PREFIX "Stopping thread\n");
          run = 0;
          break;
        }
        else
        {
          uwsgi_log(LOG_PREFIX "message received from master: %.*s\n", (int) len, buf);
        }
      }
      else if (fd == server_fd)
      {
        memset(&client_src, 0, sizeof(client_src));
        client_src_len = sizeof(client_src);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_src, &client_src_len);
        if (client_fd < 0)
        {
          uwsgi_log(LOG_PREFIX "failed to accept socket\n");
          continue;
        }
        prometheus_handle_client(client_fd);
        close(client_fd);
      }
    }
  }

  close(server_fd);
  close(u_prom.thread->pipe[1]);
  //uwsgi_log(LOG_PREFIX "Thread exit\n");
}

static void prometheus_cleanup(void)
{
  //uwsgi_log(LOG_PREFIX "Cleanup (pid: %d)\n", getpid());
  if (u_prom.thread && (u_prom.thread->pipe[0] >= 0))
  {
    uwsgi_write_nb(u_prom.thread->pipe[0], "STOP", 4, 1);
    char x;
    uwsgi_read_nb(u_prom.thread->pipe[0], &x, 1, 1);
    close(u_prom.thread->pipe[0]);
    u_prom.thread->pipe[0] = -1;
  }
}

struct uwsgi_plugin prometheus_plugin =
{
  .name = "prometheus",
  .init = prometheus_init,
  .options = uwsgi_prometheus_options,
  .on_load = prometheus_on_load,
  .master_cleanup = prometheus_cleanup
};
