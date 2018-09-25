// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2010-2011 Dreamhost
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "common/config.h"
#include "ceph_crypto.h"

#ifdef USE_NSS

// for SECMOD_RestartModules()
#include <secmod.h>
#include <nspr.h>

#endif /*USE_NSS*/

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#include <openssl/md5.h>
#endif /*USE_OPENSSL*/

#ifdef USE_NSS

static pthread_mutex_t crypto_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t crypto_refs = 0;
static NSSInitContext *crypto_context = NULL;
static pid_t crypto_init_pid = 0;

void ceph::crypto::init(CephContext *cct)
{
  pid_t pid = getpid();
  pthread_mutex_lock(&crypto_init_mutex);
  if (crypto_init_pid != pid) {
    if (crypto_init_pid > 0) {
      SECMOD_RestartModules(PR_FALSE);
    }
    crypto_init_pid = pid;
  }

  if (++crypto_refs == 1) {
    NSSInitParameters init_params;
    memset(&init_params, 0, sizeof(init_params));
    init_params.length = sizeof(init_params);

    uint32_t flags = (NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);
    if (cct->_conf->nss_db_path.empty()) {
      flags |= (NSS_INIT_NOCERTDB | NSS_INIT_NOMODDB);
    }
    crypto_context = NSS_InitContext(cct->_conf->nss_db_path.c_str(), "", "",
                                     SECMOD_DB, &init_params, flags);
  }
  pthread_mutex_unlock(&crypto_init_mutex);
  assert(crypto_context != NULL);
}

void ceph::crypto::shutdown(bool shared)
{
  pthread_mutex_lock(&crypto_init_mutex);
  assert(crypto_refs > 0);
  if (--crypto_refs == 0) {
    NSS_ShutdownContext(crypto_context);
    if (!shared) {
      PR_Cleanup();
    }
    crypto_context = NULL;
    crypto_init_pid = 0;
  }
  pthread_mutex_unlock(&crypto_init_mutex);
}

ceph::crypto::HMAC::~HMAC()
{
  PK11_DestroyContext(ctx, PR_TRUE);
  PK11_FreeSymKey(symkey);
  PK11_FreeSlot(slot);
}

#else
# error "No supported crypto implementation found."
#endif /*USE_NSS*/

#ifdef USE_OPENSSL
ceph::crypto::ssl::SHA256::SHA256() {
  mpContext = reinterpret_cast<SHA256_CTX *>(malloc(sizeof(SHA256_CTX)));
    this->Restart();
}

ceph::crypto::ssl::SHA256::~SHA256() {
  free(mpContext);
}

void ceph::crypto::ssl::SHA256::Restart() {
  SHA256_Init(mpContext);
}

void ceph::crypto::ssl::SHA256::Update(const unsigned char *input, size_t length) {
  if (length) {
    SHA256_Update(mpContext, const_cast<void *>(reinterpret_cast<const void *>(input)), length);
  }
}

void ceph::crypto::ssl::SHA256::Final(unsigned char *digest) {
  SHA256_Final(digest, mpContext);
}


ceph::crypto::ssl::SHA1::SHA1() {
  mpContext = reinterpret_cast<SHA_CTX *>(malloc(sizeof(SHA_CTX)));
  this->Restart();
}

ceph::crypto::ssl::SHA1::~SHA1() {
  free(mpContext);
}

void ceph::crypto::ssl::SHA1::Restart() {
  SHA1_Init(mpContext);
}

void ceph::crypto::ssl::SHA1::Update(const unsigned char *input, size_t length) {
  if (length) {
    SHA1_Update(mpContext, const_cast<void *>(reinterpret_cast<const void *>(input)), length);
  }
}

void ceph::crypto::ssl::SHA1::Final(unsigned char *digest) {
  SHA1_Final(digest, mpContext);
}


ceph::crypto::ssl::MD5::MD5() {
  mpContext = reinterpret_cast<MD5_CTX *>(malloc(sizeof(MD5_CTX)));
  this->Restart();
}

ceph::crypto::ssl::MD5::~MD5() {
  free(mpContext);
}

void ceph::crypto::ssl::MD5::Restart() {
  MD5_Init(mpContext);
}

void ceph::crypto::ssl::MD5::Update(const unsigned char *input, size_t length) {
  if (length) {
    MD5_Update(mpContext, const_cast<void *>(reinterpret_cast<const void *>(input)), length);
  }
}

void ceph::crypto::ssl::MD5::Final(unsigned char *digest) {
  MD5_Final(digest, mpContext);
}
#endif /*USE_OPENSSL*/
