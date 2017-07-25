#!/usr/bin/python
#
# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from keystoneclient.v2_0 import client
from keystoneclient.v3 import client as keystoneclient_v3
from keystoneclient.auth import token_endpoint
from keystoneclient import session, exceptions
from charmhelpers.core.decorators import retry_on_exception

# Early versions of keystoneclient lib do not have an explicit
# ConnectionRefused
if hasattr(exceptions, 'ConnectionRefused'):
    econnrefused = exceptions.ConnectionRefused
else:
    econnrefused = exceptions.ConnectionError


def _get_keystone_manager_class(endpoint, token, api_version):
    """Return KeystoneManager class for the given API version
    @param endpoint: the keystone endpoint to point client at
    @param token: the keystone admin_token
    @param api_version: version of the keystone api the client should use
    @returns keystonemanager class used for interrogating keystone
    """
    if api_version == 2:
        return KeystoneManager2(endpoint, token)
    if api_version == 3:
        return KeystoneManager3(endpoint, token)
    raise ValueError('No manager found for api version {}'.format(api_version))


@retry_on_exception(5, base_delay=3, exc_type=econnrefused)
def get_keystone_manager(endpoint, token, api_version=None):
    """Return a keystonemanager for the correct API version

    If api_version has not been set then create a manager based on the endpoint
    Use this manager to query the catalogue and determine which api version
    should actually be being used. Return the correct client based on that.
    Function is wrapped in a retry_on_exception to catch the case where the
    keystone service is still initialising and not responding to requests yet.
    XXX I think the keystone client should be able to do version
        detection automatically so the code below could be greatly
        simplified

    @param endpoint: the keystone endpoint to point client at
    @param token: the keystone admin_token
    @param api_version: version of the keystone api the client should use
    @returns keystonemanager class used for interrogating keystone
    """
    if api_version:
        return _get_keystone_manager_class(endpoint, token, api_version)
    else:
        if 'v2.0' in endpoint.split('/'):
            manager = _get_keystone_manager_class(endpoint, token, 2)
        else:
            manager = _get_keystone_manager_class(endpoint, token, 3)
        if endpoint.endswith('/'):
            base_ep = endpoint.rsplit('/', 2)[0]
        else:
            base_ep = endpoint.rsplit('/', 1)[0]
        svc_id = None
        for svc in manager.api.services.list():
            if svc.type == 'identity':
                svc_id = svc.id
        version = None
        for ep in manager.api.endpoints.list():
            if ep.service_id == svc_id and hasattr(ep, 'adminurl'):
                version = ep.adminurl.split('/')[-1]
        if version and version == 'v2.0':
            new_ep = base_ep + "/" + 'v2.0'
            return _get_keystone_manager_class(new_ep, token, 2)
        elif version and version == 'v3':
            new_ep = base_ep + "/" + 'v3'
            return _get_keystone_manager_class(new_ep, token, 3)
        else:
            return manager


class KeystoneManager(object):

    def resolve_domain_id(self, name):
        pass

    def resolve_role_id(self, name):
        """Find the role_id of a given role"""
        roles = [r._info for r in self.api.roles.list()]
        for r in roles:
            if name.lower() == r['name'].lower():
                return r['id']

    def resolve_service_id(self, name, service_type=None):
        """Find the service_id of a given service"""
        services = [s._info for s in self.api.services.list()]
        for s in services:
            if service_type:
                if (name.lower() == s['name'].lower() and
                        service_type == s['type']):
                    return s['id']
            else:
                if name.lower() == s['name'].lower():
                    return s['id']

    def resolve_service_id_by_type(self, type):
        """Find the service_id of a given service"""
        services = [s._info for s in self.api.services.list()]
        for s in services:
            if type == s['type']:
                return s['id']


class KeystoneManager2(KeystoneManager):

    def __init__(self, endpoint, token):
        self.api_version = 2
        self.api = client.Client(endpoint=endpoint, token=token)

    def resolve_user_id(self, name, user_domain=None):
        """Find the user_id of a given user"""
        users = [u._info for u in self.api.users.list()]
        for u in users:
            if name.lower() == u['name'].lower():
                return u['id']

    def create_endpoints(self, region, service_id, publicurl, adminurl,
                         internalurl):
        self.api.endpoints.create(region=region, service_id=service_id,
                                  publicurl=publicurl, adminurl=adminurl,
                                  internalurl=internalurl)

    def tenants_list(self):
        return self.api.tenants.list()

    def resolve_tenant_id(self, name, domain=None):
        """Find the tenant_id of a given tenant"""
        tenants = [t._info for t in self.api.tenants.list()]
        for t in tenants:
            if name.lower() == t['name'].lower():
                return t['id']

    def create_tenant(self, tenant_name, description, domain='default'):
        self.api.tenants.create(tenant_name=tenant_name,
                                description=description)

    def delete_tenant(self, tenant_id):
        self.api.tenants.delete(tenant_id)

    def create_user(self, name, password, email, tenant_id=None,
                    domain_id=None):
        self.api.users.create(name=name,
                              password=password,
                              email=email,
                              tenant_id=tenant_id)

    def update_password(self, user, password):
        self.api.users.update_password(user=user, password=password)

    def roles_for_user(self, user_id, tenant_id=None, domain_id=None):
        return self.api.roles.roles_for_user(user_id, tenant_id)

    def add_user_role(self, user, role, tenant, domain):
        self.api.roles.add_user_role(user=user, role=role, tenant=tenant)


class KeystoneManager3(KeystoneManager):

    def __init__(self, endpoint, token):
        self.api_version = 3
        keystone_auth_v3 = token_endpoint.Token(endpoint=endpoint, token=token)
        keystone_session_v3 = session.Session(auth=keystone_auth_v3)
        self.api = keystoneclient_v3.Client(session=keystone_session_v3)

    def resolve_tenant_id(self, name, domain=None):
        """Find the tenant_id of a given tenant"""
        if domain:
            domain_id = self.resolve_domain_id(domain)
        tenants = [t._info for t in self.api.projects.list()]
        for t in tenants:
            if name.lower() == t['name'].lower() and \
               (domain is None or t['domain_id'] == domain_id):
                return t['id']

    def resolve_domain_id(self, name):
        """Find the domain_id of a given domain"""
        domains = [d._info for d in self.api.domains.list()]
        for d in domains:
            if name.lower() == d['name'].lower():
                return d['id']

    def resolve_user_id(self, name, user_domain=None):
        """Find the user_id of a given user"""
        domain_id = None
        if user_domain:
            domain_id = self.resolve_domain_id(user_domain)
        for user in self.api.users.list(domain=domain_id):
            if name.lower() == user.name.lower():
                if user_domain:
                    if domain_id == user.domain_id:
                        return user.id
                else:
                    return user.id

    def create_endpoints(self, region, service_id, publicurl, adminurl,
                         internalurl):
        self.api.endpoints.create(service_id, publicurl, interface='public',
                                  region=region)
        self.api.endpoints.create(service_id, adminurl, interface='admin',
                                  region=region)
        self.api.endpoints.create(service_id, internalurl,
                                  interface='internal', region=region)

    def tenants_list(self):
        return self.api.projects.list()

    def create_domain(self, domain_name, description):
        self.api.domains.create(domain_name, description=description)

    def create_tenant(self, tenant_name, description, domain='default'):
        domain_id = self.resolve_domain_id(domain)
        self.api.projects.create(tenant_name, domain_id,
                                 description=description)

    def delete_tenant(self, tenant_id):
        self.api.projects.delete(tenant_id)

    def create_user(self, name, password, email, tenant_id=None,
                    domain_id=None):
        if not domain_id:
            domain_id = self.resolve_domain_id('default')
        if tenant_id:
            self.api.users.create(name,
                                  domain=domain_id,
                                  password=password,
                                  email=email,
                                  project=tenant_id)
        else:
            self.api.users.create(name,
                                  domain=domain_id,
                                  password=password,
                                  email=email)

    def update_password(self, user, password):
        self.api.users.update(user, password=password)

    def roles_for_user(self, user_id, tenant_id=None, domain_id=None):
        # Specify either a domain or project, not both
        if domain_id:
            return self.api.roles.list(user_id, domain=domain_id)
        else:
            return self.api.roles.list(user_id, project=tenant_id)

    def add_user_role(self, user, role, tenant, domain):
        # Specify either a domain or project, not both
        if domain:
            self.api.roles.grant(role, user=user, domain=domain)
        if tenant:
            self.api.roles.grant(role, user=user, project=tenant)

    def find_endpoint_v3(self, interface, service_id, region):
        found_eps = []
        for ep in self.api.endpoints.list():
            if ep.service_id == service_id and ep.region == region and \
                    ep.interface == interface:
                found_eps.append(ep)
        return found_eps

    def delete_old_endpoint_v3(self, interface, service_id, region, url):
        eps = self.find_endpoint_v3(interface, service_id, region)
        for ep in eps:
            if getattr(ep, 'url') != url:
                self.api.endpoints.delete(ep.id)
                return True
        return False
