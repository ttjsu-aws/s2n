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

#include <s2n.h>

#include "tls/s2n_ecc_preferences.h"
#include "tls/s2n_connection.h"
#include "crypto/s2n_ecc_evp.h"
#include "utils/s2n_safety.h"

const struct s2n_ecc_named_curve *const s2n_ecc_pref_list_20140601[] = {
    &s2n_ecc_curve_secp256r1,
    &s2n_ecc_curve_secp384r1,
};

const struct s2n_ecc_named_curve *const s2n_ecc_pref_list_20200310[] = {
    &s2n_ecc_curve_x25519,
    &s2n_ecc_curve_secp256r1,
    &s2n_ecc_curve_secp384r1,
};

const struct s2n_ecc_preferences s2n_ecc_preferences_20140601 = {
        .count = s2n_array_len(s2n_ecc_pref_list_20140601),
        .ecc_curves = s2n_ecc_pref_list_20140601,
};

const struct s2n_ecc_preferences s2n_ecc_preferences_20200310 = {
        .count = s2n_array_len(s2n_ecc_pref_list_20200310),
        .ecc_curves = s2n_ecc_pref_list_20200310,
};

static struct {
    const char *version;
    const struct s2n_ecc_preferences *preferences;
} selection[] = {
        {.version = "default", .preferences = &s2n_ecc_preferences_20140601 },
        {.version = "default_tls13", .preferences = &s2n_ecc_preferences_20200310 },
        {.version = "20200310", .preferences = &s2n_ecc_preferences_20200310 },
        {.version = "20140601", .preferences = &s2n_ecc_preferences_20140601 },
        {.version = NULL, .preferences = NULL }, /* Sentinel */
};

static int s2n_find_ecc_pref_from_version(const char *version, const struct s2n_ecc_preferences **ecc_preferences)
{
    notnull_check(version);
    notnull_check(ecc_preferences);

    for (int i = 0; selection[i].version != NULL; i++) {
        if (!strcasecmp(version, selection[i].version)) {
            *ecc_preferences = selection[i].preferences;
            return 0;
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_ECC_PREFERENCES);
}

int s2n_config_set_ecc_preferences(struct s2n_config *config, const char *version)
{
    GUARD(s2n_find_ecc_pref_from_version(version, &config->ecc_preferences));
    return 0;
}

int s2n_connection_set_ecc_preferences(struct s2n_connection *conn, const char *version)
{
    GUARD(s2n_find_cipher_pref_from_version(version, &conn->cipher_pref_override));
    return 0;
}
