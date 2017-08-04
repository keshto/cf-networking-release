# Copyright (c) 2017 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import json
import os
import sys
import etcd

from pycalico.datastore import DatastoreClient
from pycalico.datastore_datatypes import Rules, Rule

PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(PATH, os.path.join('..')))
sys.path.append(os.path.join(PATH, os.path.join('../handlers')))

from constants import *
from cf_policy_parser import CFPolicyParser

logging.basicConfig()
_log = logging.getLogger("__main__")

ETCD_AUTHORITY_DEFAULT = "127.0.0.1:2379"
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"
ETCD_ENDPOINTS_ENV = "ETCD_ENDPOINTS"

# Secure etcd with SSL environment variables and paths
ETCD_SCHEME_DEFAULT = "http"
ETCD_SCHEME_ENV = "ETCD_SCHEME"
ETCD_KEY_FILE_ENV = "ETCD_KEY_FILE"
ETCD_CERT_FILE_ENV = "ETCD_CERT_FILE"
ETCD_CA_CERT_FILE_ENV = "ETCD_CA_CERT_FILE"

CALICO_V_PATH = "/calico/v1"
CONFIG_PATH = CALICO_V_PATH + "/config/"
PROFILES_PATH = CALICO_V_PATH + "/policy/profile/"
PROFILE_PATH = PROFILES_PATH + "%(profile_id)s/"
TIER_PATH = CALICO_V_PATH + "/policy/tier/%(tier_name)s"
POLICIES_PATH = TIER_PATH + "/policy/"
POLICY_PATH = TIER_PATH + "/policy/%(policy_name)s/"

CF_DEPLOYMENT_ID = 'CF_DEPLOYMENT_ID'

ds_client = None
etcd_endpoints = None
cf_network_policy = 'cf-network-policy'
cf_namespace_id = 'cf'


def init_tier():
    default_tier_name = cf_namespace_id

    try:
        metadata = {"order": NET_POL_TIER_ORDER, "namespace": cf_namespace_id }
        ds_client.set_policy_tier_metadata(default_tier_name, metadata)
        print 'Done setting policy metadata against tier: {}'.format(default_tier_name)

        print 'Now check for policy metadata'
        metadata = ds_client.get_policy_tier_metadata(default_tier_name)
        _log.info("Policy metadata : {}".format(metadata))

    except Exception as e:
        _log.error("Exception : {}".format(e))

def load_all_policies():
    default_tier_name = cf_namespace_id

    init_tier()

    policies = set()
    try:
        policies_path = POLICIES_PATH % {"tier_name": default_tier_name}
        print 'Policies path: {}'.format(policies_path)
        etcd_policies = etcd_client.read(policies_path).children
        for child in etcd_policies:
            path = child.key
            path_entries = child.key.split('/')
            key = path_entries[len(path_entries) - 1]
            print 'Key : {}'.format(key)
            policy = json.loads(child.value)
            print 'Policy Entry : {}'.format(policy)
            #policies.add(policy)
    except etcd.EtcdKeyNotFound:
        # Means the POLICIES_PATH was not set up.  So, policy does not
        # exist.
        pass
    return policies

def update_network_policy(name, selector, ingress_rules, egress_rules=[Rule(action="allow")]):
    default_tier_name = cf_namespace_id

    rules = Rules(inbound_rules=inbound_rules,
                  outbound_rules=[Rule(action="allow")])

    # Create the network policy using the calculated selector and rules.
    client.create_policy(default_tier_name,
                         name,
                         selector,
                         order=NET_POL_ORDER,
                         rules=rules)
    _log.debug("Added/Updated policy '%s' for NetworkPolicy", name)

def delete_network_policy(name):
    default_tier_name = cf_namespace_id

    client.remove_policy(default_tier_name, name)
    _log.debug("Deleted policy '%s' for NetworkPolicy", name)

def add_update_network_policy(policy):
    default_tier_name = cf_namespace_id

    name = policy["name"]
    _log.debug("Adding new network policy: %s", name)

    try:
        parser = CFPolicyParser(policy)
        selector = parser.calculate_cf_selector()
        inbound_rules = parser.calculate_inbound_rules()
    except Exception:
        # If the Policy is malformed, log the error and kill the controller.
        # Kubernetes will restart us.
        _log.exception("Error parsing policy: %s",
                       json.dumps(policy, indent=2))
        os.exit(1)
    else:
        rules = Rules(inbound_rules=inbound_rules,
                      outbound_rules=[Rule(action="allow")])

        # Create the network policy using the calculated selector and rules.
        client.create_policy("default",
                             name,
                             selector,
                             order=NET_POL_ORDER,
                             rules=rules)
        _log.debug("Updated policy '%s' for NetworkPolicy", name)



"""
Below code from: 
projectcalico/libcalico/blob/master/calico_containers/pycalico/datastore.py
"""
def init():
    global etcd_endpoints
    global etcd_client
    global ds_client
    global cf_namespace_id
    
    etcd_endpoints = os.getenv(ETCD_ENDPOINTS_ENV, 'http://10.244.0.128:4001')
    etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)
    etcd_scheme = os.getenv(ETCD_SCHEME_ENV, ETCD_SCHEME_DEFAULT)
    etcd_key = os.getenv(ETCD_KEY_FILE_ENV, '')
    etcd_cert = os.getenv(ETCD_CERT_FILE_ENV, '')
    etcd_ca = os.getenv(ETCD_CA_CERT_FILE_ENV, '')

    if not etcd_endpoints:
         _log.error('No ETCD_ENDPOINTS variable defined in env, aborting!!')
         exit(-1)

    endpoints = [x.strip() for x in etcd_endpoints.split(",")]
    
    scheme = None
    etcd_addrs_raw = []
    for e in endpoints:
        s, a = e.split("://")
        etcd_addrs_raw.append(a)
        if scheme == None:
            scheme = s
        else:
            if scheme != s:
                raise DataStoreError(
                    "Inconsistent protocols in %s.  Value "
                    "provided is '%s'" %
                    (ETCD_ENDPOINTS_ENV, etcd_endpoints)
                )
    etcd_scheme = scheme
    addr_env = ETCD_ENDPOINTS_ENV
    scheme_env = ETCD_ENDPOINTS_ENV

    etcd_addrs = []
    for addr in etcd_addrs_raw:
        (host, port) = addr.split(":", 1)
        etcd_addrs.append((host, int(port)))

    if len(etcd_addrs) == 0:
        addr = etcd_endpoints.replace('http://', '')
        (host, port) = addr.split(":", 1)
        etcd_addrs.append((host, int(port)))

    print 'Etcd Addrs: {}'.format(etcd_addrs)
    etcd_client = etcd.Client(host=tuple(etcd_addrs),
                               protocol="http",
                               cert=etcd_key,
                               ca_cert=etcd_ca,
                               allow_reconnect=True)
    ds_client = DatastoreClient()
    cf_namespace_id = os.getenv(CF_DEPLOYMENT_ID, 'cf')

def main():
    init()
    load_all_policies()

if __name__ == "__main__":    
    main()  