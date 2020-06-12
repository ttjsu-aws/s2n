import copy
import os
import pytest
import subprocess
import time

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROVIDERS, PROTOCOLS
from common import ProviderOptions, data_bytes, Protocols
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL, Tcpdump
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", ALL_TEST_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", PROTOCOLS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_s2n_client_hello_retry_request(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(4096)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        extra_flags=['-K','none'],
        data_to_send=random_bytes,
        insecure=True,
        protocol=protocol)

    server_options = copy.copy(client_options)
    server_options.data_to_send = None
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    expected_version = get_expected_s2n_version(protocol, provider)


    for results in client.get_results():
        assert results.exception is None

    marker_found = False
    client_hello_count = 0
    server_hello_count = 0
    finished_count = 0
    marker = b"cf 21 ad 74 e5 9a 61 11 be 1d"

    for results in server.get_results():
        assert results.exception is None
        
        if marker in results.stdout:
            marker_found = True
        if b'ClientHello' in results.stdout:
            client_hello_count += 1
        if b'ServerHello' in results.stdout:
            server_hello_count += 1
        if b'], Finished' in results.stdout:
            finished_count += 1
        if marker_found and client_hello_count == 2 and server_hello_count == 2 and finished_count == 2:
            assert result.status is Status.PASSED
            break