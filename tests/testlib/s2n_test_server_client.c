/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "testlib/s2n_testlib.h"

int s2n_negotiate_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && s2n_errno == S2N_ERR_IO_BLOCKED))) {
            return -1;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && s2n_errno == S2N_ERR_IO_BLOCKED) || server_blocked == S2N_BLOCKED_ON_APPLICATION_INPUT)) {
            return -1;
        }

        tries += 1;
        if (tries == 5) {
            return -1;
        }
    } while (client_blocked || server_blocked);

    uint8_t server_shutdown = 0;
    uint8_t client_shutdown = 0;
    do {
        if (!server_shutdown) {
            int server_rc = s2n_shutdown(server_conn, &server_blocked);
            if (server_rc == 0) {
                server_shutdown = 1;
            } else if (!(server_blocked && errno == EAGAIN)) {
                return -1;
            }
        }

        if (!client_shutdown) {
            int client_rc = s2n_shutdown(client_conn, &client_blocked);
            if (client_rc == 0) {
                client_shutdown = 1;
            } else if (!(client_blocked && errno == EAGAIN)) {
                return -1;
            }
        }
    } while (!server_shutdown || !client_shutdown);

    return 0;
}


int s2n_shutdown_test_server_and_client(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    int server_rc = -1;
    int client_rc = -1;
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;
    int server_done = 0;
    int client_done = 0;

    do {
        if (!server_done) {
            s2n_errno = S2N_ERR_T_OK;
            server_rc = s2n_shutdown(server_conn, &server_blocked);

            if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED || client_done) {
/* Success, fatal error, or the peer is done and we're still blocked. */
                server_done = 1;
            }
        }
        if (!client_done) {
            s2n_errno = S2N_ERR_T_OK;
            client_rc = s2n_shutdown(client_conn, &client_blocked);

            if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED || server_done) {
/* Success, fatal error, or the peer is done and we're still blocked. */
                client_done = 1;
            }
        }
    } while (!client_done || !server_done);

    int rc = (server_rc == 0 && client_rc == 0) ? 0 : -1;
    return rc;
}
