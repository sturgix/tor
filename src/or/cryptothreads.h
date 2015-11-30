/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file cpuworker.h
 * \brief Header file for cpuworker.c.
 **/

#ifndef TOR_CRYPTOTHREADS_H
#define TOR_CRYPTOTHREADS_H

#include "workqueue.h"

void crypto_threads_init(void);
threadpool_t * get_crypto_threadpool(void);

#endif

