/*
  Copyright (c) 2015 WattGo

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include "xcass.h"

/**
 *  xcass init related functions
 */
xcass_t *
xcass_create(const char *hosts,
             unsigned int port) {

  xcass_t *xs = (xcass_t *) malloc(sizeof(*xs));
  xs->cluster = cass_cluster_new();
  xs->session = NULL;
  xs->consistency = CASS_CONSISTENCY_ONE;
  xs->page_size = -1;
  cass_cluster_set_contact_points(xs->cluster, hosts);
  cass_cluster_set_port(xs->cluster, port);
  return xs;
}

CassError
xcass_connect(xcass_t *xs,
              const char *keyspace) {

  xs->session = cass_session_new();
  CassFuture *connect;
  if(keyspace) 
    connect = cass_session_connect_keyspace(xs->session, xs->cluster,
                                            keyspace);
  else
    connect = cass_session_connect(xs->session, xs->cluster);
  
  cass_future_wait(connect);
  CassError rc = cass_future_error_code(connect);
  cass_future_free(connect);
  return rc;
}

void
xcass_close(xcass_t *xs) {
  if(xs->session) {
    CassFuture *close = cass_session_close(xs->session);
    cass_future_wait(close);
    cass_future_free(close);
  }
}

void
xcass_cleanup(xcass_t *xs) {
  xcass_close(xs);
  if(xs->cluster)
    cass_cluster_free(xs->cluster);
  if(xs->session)
    cass_session_free(xs->session);
  free(xs);
}

void
xcass_log_level(const char *level) {
  if(!strcasecmp(level, ""))
    cass_log_set_level(CASS_LOG_DISABLED);
  else if(!strcasecmp(level, "critical"))
    cass_log_set_level(CASS_LOG_CRITICAL);
  else if(!strcasecmp(level, "error"))
    cass_log_set_level(CASS_LOG_ERROR);
  else if(!strcasecmp(level, "warn"))
    cass_log_set_level(CASS_LOG_WARN);
  else if(!strcasecmp(level, "info"))
    cass_log_set_level(CASS_LOG_INFO);
  else if(!strcasecmp(level, "debug"))
    cass_log_set_level(CASS_LOG_DEBUG);
  else if(!strcasecmp(level, "trace"))
    cass_log_set_level(CASS_LOG_TRACE);
}

void
xcass_settings(xcass_t *xs,
               const char *settings, ...) {

  va_list args;
  regex_t regex;
  char *buffer = (char *) malloc(1024);
  char *buf = buffer;

  va_start(args, settings);
  memset(buffer, 0, 1024);
  vsnprintf(buffer, 1024, settings, args);
  va_end(args);

  int err = regcomp(&regex,
                    XCASS_SETTINGS_REGEX,
                    REG_EXTENDED | REG_ICASE);
  if(!err) {
    int match = 0;
    size_t nmatch = 0;
    regmatch_t *pmatch = NULL;
    int matched = 0;
    do {
      nmatch = regex.re_nsub + 1;
      pmatch = (regmatch_t *) malloc(sizeof(regmatch_t) * nmatch);
      if(pmatch) {
        match = regexec(&regex, buffer, nmatch, pmatch,
                        REG_EXTENDED | REG_ICASE);
        if(!match) {
          int i;
          int max = 0;
          for(i = 1; i < (int)nmatch; i += 2) {
            char *setting = NULL;
            char *value = NULL;

            int st = pmatch[i].rm_so;
            size_t sz = pmatch[i].rm_eo - st;
            setting = strndup(&buffer[st], sz + 1);
            setting[sz] = '\0';

            st = pmatch[i+1].rm_so;
            sz = pmatch[i+1].rm_eo - st;
            value = strndup(&buffer[st], sz + 1);
            value[sz] = '\0';

            char *p = value;
            int type = -2; // -1 double 0 int 1 char *
            while(*p) {
              if(*p >= '0' && *p <= '9')
                type = (strchr(value, '.') ? -1 : 0);
              else if((*p >= 'a' && *p <= 'z')
                || (*p >= 'A' && *p <= 'Z') || *p == '_') {
                type = 1;
                break;
              }
              p++;
            }

            int int_value = 0;
            if(!type)
              int_value = atoi(value);

            /**
             *  Dealing with double value :
             *      double double_value = 0;
             *      if(type < 0)
             *        double_value = strtod(value, NULL);
             */

            if(!strcmp(setting, "num_threads_io"))
              cass_cluster_set_num_threads_io(xs->cluster, int_value);
            else if(!strcmp(setting, "queue_size_io"))
              cass_cluster_set_queue_size_io(xs->cluster, int_value);
            else if(!strcmp(setting, "core_connections_per_host"))
              cass_cluster_set_core_connections_per_host(xs->cluster, int_value);
            else if(!strcmp(setting, "max_connections_per_host"))
              cass_cluster_set_max_connections_per_host(xs->cluster, int_value);
            else if(!strcmp(setting, "connect_timeout"))
              cass_cluster_set_connect_timeout(xs->cluster, int_value);
            else if(!strcmp(setting, "request_timeout"))
              cass_cluster_set_request_timeout(xs->cluster, int_value);
            else if(!strcmp(setting, "log_level"))
              cass_log_set_level((CassLogLevel) int_value);
            else if(!strcmp(setting, "consistency"))
              xs->consistency = (CassConsistency) int_value;
            else if(!strcmp(setting, "paging_size"))
              xs->page_size = int_value;
            else if(!strcmp(setting, "log"))
              xcass_log_level(value);
            else
              fprintf(stderr,
                      "(xcass_settings) skip unsupported option '%s'\n",
                      setting);

            free(setting);
            free(value);
            matched = 1;
            max = pmatch[i].rm_eo;
          }
          buffer += max;
        }
        else if(match == REG_NOMATCH && !matched) {
          fprintf(stderr, "'%s' didnt match any supported setting\n", buffer);
        }
        free(pmatch);
      }
      else {
          perror("malloc");
      }
    } while(!match && buffer);
    regfree(&regex);
  }
  free(buf);
}

void
xcass_auth(xcass_t *xs,
           const char *username,
           const char *password) {

  cass_cluster_set_credentials(xs->cluster, username, password);
}
