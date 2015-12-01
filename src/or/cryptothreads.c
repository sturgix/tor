/**
 * \file cryptothreads.c
 * \brief Uses the workqueue/threadpool code to farm CPU-intensive activities
 * out to subprocesses.
 *
 **/
#include "or.h"
#include "channel.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "connection_or.h"
#include "config.h"
#include "cpuworker.h"
#include "main.h"
#include "onion.h"
#include "rephist.h"
#include "router.h"
#include "workqueue.h"

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#else
#include <event.h>
#endif

static replyqueue_t *crypto_replyqueue = NULL;
static threadpool_t *crypto_threadpool = NULL;
static struct event *crypto_reply_event = NULL;

static void *
crypto_noop_new(void *arg)
{
	return (void *)NULL;
}

static void
crypto_noop_free(void *arg)
{
	return;
}

threadpool_t *
get_crypto_threadpool(void) {
  return crypto_threadpool;
}

static void
replyqueue_process_cb(evutil_socket_t sock, short events, void *arg)
{
  log_notice(LD_OR, "[cryptothreads] replyqueue_process_cb() called by libevent.");
  replyqueue_t *rq = arg;
  (void) sock;
  (void) events;
  replyqueue_process(rq);		//in common/workqueue.c. main thread calls replyfn().
}

/** Initialize the cpuworker subsystem. It is OK to call this more than once
 * during Tor's lifetime.
 */
void
crypto_threads_init(void)
{
  log_notice(LD_OR, "[cryptothreads] Initializing crypto threads.");

  if (!crypto_replyqueue) {
    crypto_replyqueue = replyqueue_new(0);
  }
  if (!crypto_reply_event) {
    crypto_reply_event = tor_event_new(tor_libevent_get_base(),
                                replyqueue_get_socket(crypto_replyqueue),
                                EV_READ|EV_PERSIST,
                                replyqueue_process_cb,
                                crypto_replyqueue);
    event_add(crypto_reply_event, NULL);
  }
  if (!crypto_threadpool) {
    crypto_threadpool = threadpool_new(1,
                                crypto_replyqueue,
                                crypto_noop_new,
                                crypto_noop_free,
                                NULL);
  }
}
