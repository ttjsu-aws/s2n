import copy
import os
import pytest
import time

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROVIDERS, PROTOCOLS
from common import Certificates, ProviderOptions, Protocols, data_bytes, Ciphers, Curves
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL])
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
def test_hrr_s2n_client_with_openssl_server(managed_process, cipher, provider, curve, protocol, certificate):
    port = next(available_ports)

    random_bytes = data_bytes(64)
    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        data_to_send=random_bytes,
        insecure=True,
        extra_flags=["-K","secp256r1"],
        protocol=protocol)
    
    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=Curves.X25519,
        protocol=protocol,
        data_to_send=None,
        insecure=True,
        key=certificate.key,
        cert=certificate.cert)

    # Passing the type of client and server as a parameter will
    # allow us to use a fixture to enumerate all possibilities.
    server = managed_process(provider, server_options, timeout=5)
    client = managed_process(S2N, client_options, timeout=5)

    # The client should connect and return without error
    for results in client.get_results():
        assert results.exit_code == 0

    # Start of HRR random data which will be printed in the
    # client process output
    marker_found = False
    client_hello_count = 0
    server_hello_count = 0 
    finished_count = 0
    marker = b"cf 21 ad 74 e5 9a 61 11 be 1d"

    # S2N should indicate the procotol version in a successful connection.
    for results in server.get_results():

        if marker in results.stdout:
            marker_found = True
        if b'client hello' in results.stdout:
            client_hello_count += 1
        if b'server hello' in results.stdout:
            server_hello_count += 1
        if b'finished' in results.stdout:
            finished_count += 1
        if marker_found and client_hello_count == 2 and server_hello_count == 2 and finished_count == 2:
            assert result.status is Status.PASSED
            break

