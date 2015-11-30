/* Copyright (c) 2003-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

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

#if 0
static void queue_pending_tasks(void);

typedef struct worker_state_s {
  int generation;
  server_onion_keys_t *onion_keys;
} worker_state_t;

static void *
worker_state_new(void *arg)
{
  worker_state_t *ws;
  (void)arg;
  ws = tor_malloc_zero(sizeof(worker_state_t));
  ws->onion_keys = server_onion_keys_new();
  return ws;
}
static void
worker_state_free(void *arg)
{
  worker_state_t *ws = arg;
  server_onion_keys_free(ws->onion_keys);
  tor_free(ws);
}
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
  replyqueue_process(rq);		//common/workqueue.c in this func, main thread calls reply_fn()
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

#if 0
/** Magic numbers to make sure our cpuworker_requests don't grow any
 * mis-framing bugs. */
#define CPUWORKER_REQUEST_MAGIC 0xda4afeed
#define CPUWORKER_REPLY_MAGIC 0x5eedf00d

/** A request sent to a cpuworker. */
typedef struct cpuworker_request_t {
  /** Magic number; must be CPUWORKER_REQUEST_MAGIC. */
  uint32_t magic;

  /** Flag: Are we timing this request? */
  unsigned timed : 1;
  /** If we're timing this request, when was it sent to the cpuworker? */
  struct timeval started_at;

  /** A create cell for the cpuworker to process. */
  create_cell_t create_cell;

  /* Turn the above into a tagged union if needed. */
} cpuworker_request_t;

/** A reply sent by a cpuworker. */
typedef struct cpuworker_reply_t {
  /** Magic number; must be CPUWORKER_REPLY_MAGIC. */
  uint32_t magic;

  /** True iff we got a successful request. */
  uint8_t success;

  /** Are we timing this request? */
  unsigned int timed : 1;
  /** What handshake type was the request? (Used for timing) */
  uint16_t handshake_type;
  /** When did we send the request to the cpuworker? */
  struct timeval started_at;
  /** Once the cpuworker received the request, how many microseconds did it
   * take? (This shouldn't overflow; 4 billion micoseconds is over an hour,
   * and we'll never have an onion handshake that takes so long.) */
  uint32_t n_usec;

  /** Output of processing a create cell
   *
   * @{
   */
  /** The created cell to send back. */
  created_cell_t created_cell;
  /** The keys to use on this circuit. */
  uint8_t keys[CPATH_KEY_MATERIAL_LEN];
  /** Input to use for authenticating introduce1 cells. */
  uint8_t rend_auth_material[DIGEST_LEN];
} cpuworker_reply_t;

typedef struct cpuworker_job_u {
  or_circuit_t *circ;
  union {
    cpuworker_request_t request;
    cpuworker_reply_t reply;
  } u;
} cpuworker_job_t;

static workqueue_reply_t
update_state_threadfn(void *state_, void *work_)
{
  worker_state_t *state = state_;
  worker_state_t *update = work_;
  server_onion_keys_free(state->onion_keys);
  state->onion_keys = update->onion_keys;
  update->onion_keys = NULL;
  ++state->generation;
  return WQ_RPL_REPLY;
}

/** Called when the onion key has changed so update all CPU worker(s) with
 * new function pointers with which a new state will be generated.
 */
void
cpuworkers_rotate_keyinfo(void)
{
  if (!threadpool) {
    /* If we're a client, then we won't have cpuworkers, and we won't need
     * to tell them to rotate their state.
     */
    return;
  }
  if (threadpool_queue_update(threadpool,
                              worker_state_new,
                              update_state_threadfn,
                              worker_state_free,
                              NULL)) {
    log_warn(LD_OR, "Failed to queue key update for worker threads.");
  }
}

/** Indexed by handshake type: how many onionskins have we processed and
 * counted of that type? */
static uint64_t onionskins_n_processed[MAX_ONION_HANDSHAKE_TYPE+1];
/** Indexed by handshake type, corresponding to the onionskins counted in
 * onionskins_n_processed: how many microseconds have we spent in cpuworkers
 * processing that kind of onionskin? */
static uint64_t onionskins_usec_internal[MAX_ONION_HANDSHAKE_TYPE+1];
/** Indexed by handshake type, corresponding to onionskins counted in
 * onionskins_n_processed: how many microseconds have we spent waiting for
 * cpuworkers to give us answers for that kind of onionskin?
 */
static uint64_t onionskins_usec_roundtrip[MAX_ONION_HANDSHAKE_TYPE+1];

/** If any onionskin takes longer than this, we clip them to this
 * time. (microseconds) */
#define MAX_BELIEVABLE_ONIONSKIN_DELAY (2*1000*1000)

/** Return true iff we'd like to measure a handshake of type
 * <b>onionskin_type</b>. Call only from the main thread. */
static int
should_time_request(uint16_t onionskin_type)
{
  /* If we've never heard of this type, we shouldn't even be here. */
  if (onionskin_type > MAX_ONION_HANDSHAKE_TYPE)
    return 0;
  /* Measure the first N handshakes of each type, to ensure we have a
   * sample */
  if (onionskins_n_processed[onionskin_type] < 4096)
    return 1;
  /** Otherwise, measure with P=1/128.  We avoid doing this for every
   * handshake, since the measurement itself can take a little time. */
  return tor_weak_random_one_in_n(&request_sample_rng, 128);
}


/** Handle a reply from the worker threads. */
static void
cpuworker_onion_handshake_replyfn(void *work_)
{
  cpuworker_job_t *job = work_;
  cpuworker_reply_t rpl;
  or_circuit_t *circ = NULL;

  tor_assert(total_pending_tasks > 0);
  --total_pending_tasks;

  /* Could avoid this, but doesn't matter. */
  memcpy(&rpl, &job->u.reply, sizeof(rpl));

  tor_assert(rpl.magic == CPUWORKER_REPLY_MAGIC);

  if (rpl.timed && rpl.success &&
      rpl.handshake_type <= MAX_ONION_HANDSHAKE_TYPE) {
    /* Time how long this request took. The handshake_type check should be
       needless, but let's leave it in to be safe. */
    struct timeval tv_end, tv_diff;
    int64_t usec_roundtrip;
    tor_gettimeofday(&tv_end);
    timersub(&tv_end, &rpl.started_at, &tv_diff);
    usec_roundtrip = ((int64_t)tv_diff.tv_sec)*1000000 + tv_diff.tv_usec;
    if (usec_roundtrip >= 0 &&
        usec_roundtrip < MAX_BELIEVABLE_ONIONSKIN_DELAY) {
      ++onionskins_n_processed[rpl.handshake_type];
      onionskins_usec_internal[rpl.handshake_type] += rpl.n_usec;
      onionskins_usec_roundtrip[rpl.handshake_type] += usec_roundtrip;
      if (onionskins_n_processed[rpl.handshake_type] >= 500000) {
        /* Scale down every 500000 handshakes.  On a busy server, that's
         * less impressive than it sounds. */
        onionskins_n_processed[rpl.handshake_type] /= 2;
        onionskins_usec_internal[rpl.handshake_type] /= 2;
        onionskins_usec_roundtrip[rpl.handshake_type] /= 2;
      }
    }
  }

  circ = job->circ;

  log_debug(LD_OR,
            "Unpacking cpuworker reply %p, circ=%p, success=%d",
            job, circ, rpl.success);

  if (circ->base_.magic == DEAD_CIRCUIT_MAGIC) {
    /* The circuit was supposed to get freed while the reply was
     * pending. Instead, it got left for us to free so that we wouldn't freak
     * out when the job->circ field wound up pointing to nothing. */
    log_debug(LD_OR, "Circuit died while reply was pending. Freeing memory.");
    circ->base_.magic = 0;
    tor_free(circ);
    goto done_processing;
  }

  circ->workqueue_entry = NULL;

  if (TO_CIRCUIT(circ)->marked_for_close) {
    /* We already marked this circuit; we can't call it open. */
    log_debug(LD_OR,"circuit is already marked.");
    goto done_processing;
  }

  if (rpl.success == 0) {
    log_debug(LD_OR,
              "decoding onionskin failed. "
              "(Old key or bad software.) Closing.");
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_TORPROTOCOL);
    goto done_processing;
  }

  if (onionskin_answer(circ,
                       &rpl.created_cell,
                       (const char*)rpl.keys,
                       rpl.rend_auth_material) < 0) {
    log_warn(LD_OR,"onionskin_answer failed. Closing.");
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
    goto done_processing;
  }
  log_debug(LD_OR,"onionskin_answer succeeded. Yay.");

 done_processing:
  memwipe(&rpl, 0, sizeof(rpl));
  memwipe(job, 0, sizeof(*job));
  tor_free(job);
  queue_pending_tasks();
}

/** Implementation function for onion handshake requests. */
static workqueue_reply_t
cpuworker_onion_handshake_threadfn(void *state_, void *work_)
{
  worker_state_t *state = state_;
  cpuworker_job_t *job = work_;

  /* variables for onion processing */
  server_onion_keys_t *onion_keys = state->onion_keys;
  cpuworker_request_t req;
  cpuworker_reply_t rpl;

  memcpy(&req, &job->u.request, sizeof(req));

  tor_assert(req.magic == CPUWORKER_REQUEST_MAGIC);
  memset(&rpl, 0, sizeof(rpl));

  const create_cell_t *cc = &req.create_cell;
  created_cell_t *cell_out = &rpl.created_cell;
  struct timeval tv_start = {0,0}, tv_end;
  int n;
  rpl.timed = req.timed;
  rpl.started_at = req.started_at;
  rpl.handshake_type = cc->handshake_type;
  if (req.timed)
    tor_gettimeofday(&tv_start);
  n = onion_skin_server_handshake(cc->handshake_type,
                                  cc->onionskin, cc->handshake_len,
                                  onion_keys,
                                  cell_out->reply,
                                  rpl.keys, CPATH_KEY_MATERIAL_LEN,
                                  rpl.rend_auth_material);
  if (n < 0) {
    /* failure */
    log_debug(LD_OR,"onion_skin_server_handshake failed.");
    memset(&rpl, 0, sizeof(rpl));
    rpl.success = 0;
  } else {
    /* success */
    log_debug(LD_OR,"onion_skin_server_handshake succeeded.");
    cell_out->handshake_len = n;
    switch (cc->cell_type) {
    case CELL_CREATE:
      cell_out->cell_type = CELL_CREATED; break;
    case CELL_CREATE2:
      cell_out->cell_type = CELL_CREATED2; break;
    case CELL_CREATE_FAST:
      cell_out->cell_type = CELL_CREATED_FAST; break;
    default:
      tor_assert(0);
      return WQ_RPL_SHUTDOWN;
    }
    rpl.success = 1;
  }
  rpl.magic = CPUWORKER_REPLY_MAGIC;
  if (req.timed) {
    struct timeval tv_diff;
    int64_t usec;
    tor_gettimeofday(&tv_end);
    timersub(&tv_end, &tv_start, &tv_diff);
    usec = ((int64_t)tv_diff.tv_sec)*1000000 + tv_diff.tv_usec;
    if (usec < 0 || usec > MAX_BELIEVABLE_ONIONSKIN_DELAY)
      rpl.n_usec = MAX_BELIEVABLE_ONIONSKIN_DELAY;
    else
      rpl.n_usec = (uint32_t) usec;
  }

  memcpy(&job->u.reply, &rpl, sizeof(rpl));

  memwipe(&req, 0, sizeof(req));
  memwipe(&rpl, 0, sizeof(req));
  return WQ_RPL_REPLY;
}

/** Take pending tasks from the queue and assign them to cpuworkers. */
static void
queue_pending_tasks(void)
{
  or_circuit_t *circ;
  create_cell_t *onionskin = NULL;

  while (total_pending_tasks < max_pending_tasks) {
    circ = onion_next_task(&onionskin);

    if (!circ)
      return;

    if (assign_onionskin_to_cpuworker(circ, onionskin))
      log_warn(LD_OR,"assign_to_cpuworker failed. Ignoring.");
  }
}

/** Try to tell a cpuworker to perform the public key operations necessary to
 * respond to <b>onionskin</b> for the circuit <b>circ</b>.
 *
 * Return 0 if we successfully assign the task, or -1 on failure.
 */
int
assign_onionskin_to_cpuworker(or_circuit_t *circ,
                              create_cell_t *onionskin)
{
  workqueue_entry_t *queue_entry;
  cpuworker_job_t *job;
  cpuworker_request_t req;
  int should_time;

  tor_assert(threadpool);

  if (!circ->p_chan) {
    log_info(LD_OR,"circ->p_chan gone. Failing circ.");
    tor_free(onionskin);
    return -1;
  }

  if (total_pending_tasks >= max_pending_tasks) {
    log_debug(LD_OR,"No idle cpuworkers. Queuing.");
    if (onion_pending_add(circ, onionskin) < 0) {
      tor_free(onionskin);
      return -1;
    }
    return 0;
  }

  if (connection_or_digest_is_known_relay(circ->p_chan->identity_digest))
    rep_hist_note_circuit_handshake_assigned(onionskin->handshake_type);

  should_time = should_time_request(onionskin->handshake_type);
  memset(&req, 0, sizeof(req));
  req.magic = CPUWORKER_REQUEST_MAGIC;
  req.timed = should_time;

  memcpy(&req.create_cell, onionskin, sizeof(create_cell_t));

  tor_free(onionskin);

  if (should_time)
    tor_gettimeofday(&req.started_at);

  job = tor_malloc_zero(sizeof(cpuworker_job_t));
  job->circ = circ;
  memcpy(&job->u.request, &req, sizeof(req));
  memwipe(&req, 0, sizeof(req));

  ++total_pending_tasks;
  queue_entry = threadpool_queue_work(threadpool,
                                      cpuworker_onion_handshake_threadfn,
                                      cpuworker_onion_handshake_replyfn,
                                      job);
  if (!queue_entry) {
    log_warn(LD_BUG, "Couldn't queue work on threadpool");
    tor_free(job);
    return -1;
  }

  log_debug(LD_OR, "Queued task %p (qe=%p, circ=%p)",
            job, queue_entry, job->circ);

  circ->workqueue_entry = queue_entry;

  return 0;
}

/** If <b>circ</b> has a pending handshake that hasn't been processed yet,
 * remove it from the worker queue. */
void
cpuworker_cancel_circ_handshake(or_circuit_t *circ)
{
  cpuworker_job_t *job;
  if (circ->workqueue_entry == NULL)
    return;

  job = workqueue_entry_cancel(circ->workqueue_entry);
  if (job) {
    /* It successfully cancelled. */
    memwipe(job, 0xe0, sizeof(*job));
    tor_free(job);
    tor_assert(total_pending_tasks > 0);
    --total_pending_tasks;
    /* if (!job), this is done in cpuworker_onion_handshake_replyfn. */
    circ->workqueue_entry = NULL;
  }
}
#endif
