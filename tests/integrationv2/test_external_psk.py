import copy
import os
import pytest
import time

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS
from common import ProviderOptions, Protocols, data_bytes, Curves
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name

# Known values from https://tools.ietf.org/html/rfc8448#section-4 
s2n_known_value_psk = '--psk shared_identity,'\
                      '123456,'\
                      'S2N_PSK_HMAC_SHA256'

s2n_client_only_psk = '--psk s2n_client_psk_identity,'\
                      'aea617646faaea6d2dfgfgd1d2827db279,'\
                      'S2N_PSK_HMAC_SHA384'\

s2n_server_only_psk = '--psk s2n_server_psk_identity,'\
                      'aea61709390508060401050f3d2827db27,'\
                      'S2N_PSK_HMAC_SHA256'\

s2n_invalid_hmac_psk = '--psk psk_identity,'\
                       'aea617646faaea6d2dfgfgd1d2827db279,'\
                       'S2N_PSK_HMAC_SHA512'\

openssl_known_value_psk = '-psk_identity shared_identity --psk '\
                          '4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3 '\

openssl_server_only_psk = '-psk_identity openssl_server_psk_identity '\
                          '--psk 4ecd0eb6ec3b4d87f5d6028f922ca4c5851a1311c9e621311c9e2e1c4f3 '\

openssl_client_only_psk = '-psk_identity openssl_client_psk_identity '\
                          '--psk 4ecd0eb6ec3b4d872c035d6494dc486d2c8a34cb33fa90bf1b002e1c4f3'\



S2N_CLIENT_PSK_PARAMETERS = [ 
    ['--psk', 's2n_client_psk_identity,1234565432,S2N_PSK_HMAC_SHA384'], 
    ['--psk', 'shared_identity,123456,S2N_PSK_HMAC_SHA256'],
]

S2N_SERVER_PSK_PARAMETERS = [
    ['--psk', 's2n_server_psk_identity,2345654,S2N_PSK_HMAC_SHA256'],
    ['--psk', 'shared_identity,123456,S2N_PSK_HMAC_SHA256'],
]

OPENSSL_SERVER_PSK_PARAMETERS = [
    [openssl_server_only_psk + '-nocert'],
    [openssl_known_value_psk + '-nocert']
]

OPENSSL_CLIENT_PSK_PARAMETERS = [
    [openssl_client_only_psk],
    [openssl_known_value_psk]
]

def s2n_assert_chosen_psk(idx, results, psk_params):
    if idx == 0: 
        assert b"Chosen PSK wire index" not in results.stdout
        assert results.exit_code != 0
    elif idx == 1 or idx == 2: 
        assert bytes("Chosen PSK wire index:".encode('utf-8')) in results.stderr
        assert b"Chosen PSK type: S2N_PSK_TYPE_EXTERNAL" in results.stdout
        assert bytes("Chosen PSK identity size: {}".format(len(psk_params.split(",")[0][3:])).encode('utf-8')) in results.stdout
        assert bytes("Chosen PSK identity data: {}".format(psk_params.split(",")[0][3:]).encode('utf-8')) in results.stdout
        assert b"Chosen PSK obfuscated ticket age: 0" in results.stdout
        assert results.exit_code == 0
    elif idx == 3: 
        assert results.exit_code != 0

@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("client_psk_params", S2N_CLIENT_PSK_PARAMETERS, ids=get_parameter_name)
def test_external_psk_s2nc_with_s2nd(managed_process, cipher, client_psk_params):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=S2N.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        extra_flags=client_psk_params,
        protocol=Protocols.TLS13)
    
    idx = S2N_CLIENT_PSK_PARAMETERS.index(client_psk_params)
    server_psk_params = S2N_SERVER_PSK_PARAMETERS[idx]

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = S2N.ServerMode
    server_options.extra_flags = server_psk_params

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    idx = S2N_CLIENT_PSK_PARAMETERS.index(client_psk_params)
    for results in client.get_results():
        s2n_assert_chosen_psk(idx, results, client_psk_params)

    idx = S2N_SERVER_PSK_PARAMETERS.index(server_psk_params)
    for results in server.get_results():
        s2n_assert_chosen_psk(idx, results, server_psk_params)
        assert results.exception is None

