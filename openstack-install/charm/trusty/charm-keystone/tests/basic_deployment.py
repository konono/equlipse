#!/usr/bin/env python
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

"""
Basic keystone amulet functional tests.
"""

import amulet
import json
import os
import yaml

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

from charmhelpers.contrib.openstack.amulet.utils import (
    OpenStackAmuletUtils,
    DEBUG,
    # ERROR
)
import keystoneclient
from keystoneauth1 import exceptions as ksauth1_exceptions

# Use DEBUG to turn on debug logging
u = OpenStackAmuletUtils(DEBUG)


class KeystoneBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic keystone deployment."""

    DEFAULT_DOMAIN = 'default'

    def __init__(self, series=None, openstack=None,
                 source=None, git=False, stable=False):
        """Deploy the entire test environment."""
        super(KeystoneBasicDeployment, self).__init__(series, openstack,
                                                      source, stable)
        if self.is_liberty_or_newer():
            self.keystone_num_units = 3
        else:
            # issues with starting haproxy when clustered on trusty with
            # icehouse and kilo. See LP #1648396
            self.keystone_num_units = 1
        self.keystone_api_version = 2
        self.git = git
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()

        u.log.info('Waiting on extended status checks...')
        self.exclude_services = []
        self._auto_wait_for_status(exclude_services=self.exclude_services)

        self.d.sentry.wait()
        self._initialize_tests()

    def _assert_services(self, should_run):
        if self.is_liberty_or_newer():
            services = ("apache2", "haproxy")
        else:
            services = ("keystone-all", "apache2", "haproxy")
        for unit in self.keystone_sentries:
            u.get_unit_process_ids(
                {unit: services}, expect_success=should_run)

    def _add_services(self):
        """Add services

           Add the services that we're testing, where keystone is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'keystone', 'units': self.keystone_num_units}
        other_services = [
            {'name': 'percona-cluster', 'constraints': {'mem': '3072M'}},
            {'name': 'rabbitmq-server'},  # satisfy wrkload stat
            {'name': 'cinder'},
        ]
        super(KeystoneBasicDeployment, self)._add_services(this_service,
                                                           other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {'keystone:shared-db': 'percona-cluster:shared-db',
                     'cinder:shared-db': 'percona-cluster:shared-db',
                     'cinder:amqp': 'rabbitmq-server:amqp',
                     'cinder:identity-service': 'keystone:identity-service'}
        super(KeystoneBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        keystone_config = {
            'admin-password': 'openstack',
            'admin-token': 'ubuntutesting',
            'preferred-api-version': self.keystone_api_version,
        }

        if self.git:
            amulet_http_proxy = os.environ.get('AMULET_HTTP_PROXY')

            reqs_repo = 'git://github.com/openstack/requirements'
            keystone_repo = 'git://github.com/openstack/keystone'
            if self._get_openstack_release() == self.trusty_icehouse:
                reqs_repo = 'git://github.com/coreycb/requirements'
                keystone_repo = 'git://github.com/coreycb/keystone'

            branch = 'stable/' + self._get_openstack_release_string()

            openstack_origin_git = {
                'repositories': [
                    {'name': 'requirements',
                     'repository': reqs_repo,
                     'branch': branch},
                    {'name': 'keystone',
                     'repository': keystone_repo,
                     'branch': branch},
                ],
                'directory': '/mnt/openstack-git',
                'http_proxy': amulet_http_proxy,
                'https_proxy': amulet_http_proxy,
            }
            keystone_config['openstack-origin-git'] = \
                yaml.dump(openstack_origin_git)

        pxc_config = {
            'dataset-size': '25%',
            'max-connections': 1000,
            'root-password': 'ChangeMe123',
            'sst-password': 'ChangeMe123',
        }
        cinder_config = {'block-device': 'vdb',
                         'glance-api-version': '2',
                         'overwrite': 'true',
                         'ephemeral-unmount': '/mnt'}
        configs = {
            'keystone': keystone_config,
            'percona-cluster': pxc_config,
            'cinder': cinder_config,
        }
        super(KeystoneBasicDeployment, self)._configure_services(configs)

    def set_api_version(self, api_version):
        u.log.debug('Setting preferred-api-version={}'.format(api_version))
        se_rels = []
        for i in range(0, self.keystone_num_units):
            se_rels.append(
                (self.keystone_sentries[i], 'cinder:identity-service'),
            )
        # Make config change, wait for propagation
        u.keystone_configure_api_version(se_rels, self, api_version)

        # Success if we get here, get and store client.
        if api_version == 2:
            self.keystone_v2 = self.get_keystone_client(api_version=2)
        else:
            self.keystone_v3 = self.get_keystone_client(api_version=3)
        self.keystone_api_version = api_version

    def get_keystone_client(self, api_version=None, keystone_ip=None):
        if keystone_ip is None:
            keystone_ip = self.keystone_ip
        if api_version == 2:
            return u.authenticate_keystone_admin(self.keystone_sentries[0],
                                                 user='admin',
                                                 password='openstack',
                                                 tenant='admin',
                                                 api_version=api_version,
                                                 keystone_ip=keystone_ip)
        else:
            return u.authenticate_keystone_admin(self.keystone_sentries[0],
                                                 user='admin',
                                                 password='openstack',
                                                 api_version=api_version,
                                                 keystone_ip=keystone_ip)

    def create_users_v2(self):
        # Create a demo tenant/role/user
        self.demo_tenant = 'demoTenant'
        self.demo_role = 'demoRole'
        self.demo_user = 'demoUser'
        if not u.tenant_exists(self.keystone_v2, self.demo_tenant):
            tenant = self.keystone_v2.tenants.create(
                tenant_name=self.demo_tenant,
                description='demo tenant',
                enabled=True)
            self.keystone_v2.roles.create(name=self.demo_role)
            self.keystone_v2.users.create(name=self.demo_user,
                                          password='password',
                                          tenant_id=tenant.id,
                                          email='demo@demo.com')

            # Authenticate keystone demo
            self.keystone_demo = u.authenticate_keystone_user(
                self.keystone_v2, user=self.demo_user,
                password='password', tenant=self.demo_tenant)

    def create_users_v3(self):
        # Create a demo tenant/role/user
        self.demo_project = 'demoProject'
        self.demo_user_v3 = 'demoUserV3'
        self.demo_domain_admin = 'demoDomainAdminV3'
        self.demo_domain = 'demoDomain'
        try:
            domain = self.keystone_v3.domains.find(name=self.demo_domain)
        except keystoneclient.exceptions.NotFound:
            domain = self.keystone_v3.domains.create(
                self.demo_domain,
                description='Demo Domain',
                enabled=True
            )

        try:
            self.keystone_v3.projects.find(name=self.demo_project)
        except keystoneclient.exceptions.NotFound:
            self.keystone_v3.projects.create(
                self.demo_project,
                domain,
                description='Demo Project',
                enabled=True,
            )

        try:
            self.keystone_v3.roles.find(name=self.demo_role)
        except keystoneclient.exceptions.NotFound:
            self.keystone_v3.roles.create(name=self.demo_role)

        if not self.find_keystone_v3_user(self.keystone_v3,
                                          self.demo_user_v3,
                                          self.demo_domain):
            self.keystone_v3.users.create(
                self.demo_user_v3,
                domain=domain.id,
                project=self.demo_project,
                password='password',
                email='demov3@demo.com',
                description='Demo',
                enabled=True)

        try:
            self.keystone_v3.roles.find(name='Admin')
        except keystoneclient.exceptions.NotFound:
            self.keystone_v3.roles.create(name='Admin')

        if not self.find_keystone_v3_user(self.keystone_v3,
                                          self.demo_domain_admin,
                                          self.demo_domain):
            user = self.keystone_v3.users.create(
                self.demo_domain_admin,
                domain=domain.id,
                project=self.demo_project,
                password='password',
                email='demoadminv3@demo.com',
                description='Demo Admin',
                enabled=True)

            role = self.keystone_v3.roles.find(name='Admin')
            u.log.debug("self.keystone_v3.roles.grant('{}', user='{}', "
                        "domain='{}')".format(role.id, user.id, domain.id))
            self.keystone_v3.roles.grant(
                role.id,
                user=user.id,
                domain=domain.id)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.pxc_sentry = self.d.sentry['percona-cluster'][0]
        self.keystone_sentries = []
        for i in range(0, self.keystone_num_units):
            self.keystone_sentries.append(self.d.sentry['keystone'][i])
        self.cinder_sentry = self.d.sentry['cinder'][0]
        u.log.debug('openstack release val: {}'.format(
            self._get_openstack_release()))
        u.log.debug('openstack release str: {}'.format(
            self._get_openstack_release_string()))
        self.keystone_ip = self.keystone_sentries[0].relation(
            'shared-db',
            'percona-cluster:shared-db')['private-address']
        self.set_api_version(2)
        # Authenticate keystone admin
        self.keystone_v2 = self.get_keystone_client(api_version=2)
        self.keystone_v3 = self.get_keystone_client(api_version=3)
        self.create_users_v2()

    def test_100_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        services = {
            self.cinder_sentry: ['cinder-scheduler',
                                 'cinder-volume']
        }
        if self._get_openstack_release() >= self.xenial_ocata:
            services.update({self.cinder_sentry: ['apache2']})
        else:
            services.update({self.cinder_sentry: ['cinder-api']})

        if self.is_liberty_or_newer():
            for i in range(0, self.keystone_num_units):
                services.update({self.keystone_sentries[i]: ['apache2']})
        else:
            services.update({self.keystone_sentries[0]: ['keystone']})

        ret = u.validate_services_by_name(services)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def validate_keystone_tenants(self, client):
        """Verify all existing tenants."""
        u.log.debug('Checking keystone tenants...')
        expected = [
            {'name': 'services',
             'enabled': True,
             'description': 'Created by Juju',
             'id': u.not_null},
            {'name': 'demoTenant',
             'enabled': True,
             'description': 'demo tenant',
             'id': u.not_null},
            {'name': 'admin',
             'enabled': True,
             'description': 'Created by Juju',
             'id': u.not_null}
        ]
        if self.keystone_api_version == 2:
            actual = client.tenants.list()
        else:
            actual = client.projects.list()

        ret = u.validate_tenant_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_102_keystone_tenants(self):
        self.set_api_version(2)
        self.validate_keystone_tenants(self.keystone_v2)

    def validate_keystone_roles(self, client):
        """Verify all existing roles."""
        u.log.debug('Checking keystone roles...')
        expected = [
            {'name': 'demoRole',
             'id': u.not_null},
            {'name': 'Admin',
             'id': u.not_null}
        ]
        actual = client.roles.list()

        ret = u.validate_role_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_104_keystone_roles(self):
        self.set_api_version(2)
        self.validate_keystone_roles(self.keystone_v2)

    def validate_keystone_users(self, client):
        """Verify all existing roles."""
        u.log.debug('Checking keystone users...')
        base = [
            {'name': 'demoUser',
             'enabled': True,
             'id': u.not_null,
             'email': 'demo@demo.com'},
            {'name': 'admin',
             'enabled': True,
             'id': u.not_null,
             'email': 'juju@localhost'},
            {'name': 'cinder_cinderv2',
             'enabled': True,
             'id': u.not_null,
             'email': u'juju@localhost'}
        ]
        expected = []
        for user_info in base:
            if self.keystone_api_version == 2:
                user_info['tenantId'] = u.not_null
            else:
                user_info['default_project_id'] = u.not_null
            expected.append(user_info)
        if self.keystone_api_version == 2:
            actual = client.users.list()
        else:
            # Ensure list is scoped to the default domain
            # when checking v3 users (v2->v3 upgrade check)
            actual = client.users.list(
                domain=client.domains.find(name=self.DEFAULT_DOMAIN).id
            )
        ret = u.validate_user_data(expected, actual,
                                   api_version=self.keystone_api_version)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def find_keystone_v3_user(self, client, username, domain):
        """Find a user within a specified keystone v3 domain"""
        domain_users = client.users.list(
            domain=client.domains.find(name=domain).id
        )
        for user in domain_users:
            if username.lower() == user.name.lower():
                return user
        return None

    def test_106_keystone_users(self):
        self.set_api_version(2)
        self.validate_keystone_users(self.keystone_v2)

    def is_liberty_or_newer(self):
        # os_release = self._get_openstack_release_string()
        os_release = self._get_openstack_release()
        # if os_release >= 'liberty':
        if os_release >= self.trusty_liberty:
            return True
        else:
            u.log.info('Skipping test, {} < liberty'.format(os_release))
            return False

    def is_mitaka_or_newer(self):
        # os_release = self._get_openstack_release_string()
        os_release = self._get_openstack_release()
        # if os_release >= 'mitaka':
        if os_release >= self.xenial_mitaka:
            return True
        else:
            u.log.info('Skipping test, {} < mitaka'.format(os_release))
            return False

    def test_112_keystone_tenants(self):
        if self.is_liberty_or_newer():
            self.set_api_version(3)
            self.validate_keystone_tenants(self.keystone_v3)

    def test_114_keystone_tenants(self):
        if self.is_liberty_or_newer():
            self.set_api_version(3)
            self.validate_keystone_roles(self.keystone_v3)

    def test_116_keystone_users(self):
        if self.is_liberty_or_newer():
            self.set_api_version(3)
            self.validate_keystone_users(self.keystone_v3)

    def test_118_keystone_users(self):
        if self.is_liberty_or_newer():
            self.set_api_version(3)
            self.create_users_v3()
            actual_user = self.find_keystone_v3_user(self.keystone_v3,
                                                     self.demo_user_v3,
                                                     self.demo_domain)
            assert actual_user is not None
            expect = {
                'default_project_id': self.demo_project,
                'email': 'demov3@demo.com',
                'name': self.demo_user_v3,
            }
            for key in expect.keys():
                u.log.debug('Checking user {} {} is {}'.format(
                    self.demo_user_v3,
                    key,
                    expect[key])
                )
                assert expect[key] == getattr(actual_user, key)

    def test_120_keystone_domains(self):
        if self.is_liberty_or_newer():
            self.set_api_version(3)
            self.create_users_v3()
            actual_domain = self.keystone_v3.domains.find(
                name=self.demo_domain
            )
            expect = {
                'name': self.demo_domain,
            }
            for key in expect.keys():
                u.log.debug('Checking domain {} {} is {}'.format(
                    self.demo_domain,
                    key,
                    expect[key])
                )
                assert expect[key] == getattr(actual_domain, key)

    def test_121_keystone_demo_domain_admin_access(self):
        """Verify that end-user domain admin does not have elevated
           privileges. Catch regressions like LP#1651989"""
        if self.is_mitaka_or_newer():
            u.log.debug('Checking keystone end-user domain admin access...')
            self.set_api_version(3)
            # Authenticate as end-user domain admin and verify that we have
            # appropriate access.
            client = u.authenticate_keystone(
                self.keystone_sentries[0].info['public-address'],
                username=self.demo_domain_admin,
                password='password',
                api_version=3,
                user_domain_name=self.demo_domain,
                domain_name=self.demo_domain,
            )

            try:
                # Expect failure
                client.domains.list()
            except Exception as e:
                message = ('Retrieve domain list as end-user domain admin '
                           'NOT allowed...OK ({})'.format(e))
                u.log.debug(message)
                pass
            else:
                message = ('Retrieve domain list as end-user domain admin '
                           'allowed')
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_122_keystone_project_scoped_admin_access(self):
        """Verify that user admin in domain admin_domain has access to
           identity-calls guarded by rule:cloud_admin when using project
           scoped token."""
        if self.is_mitaka_or_newer():
            u.log.debug('Checking keystone project scoped admin access...')
            self.set_api_version(3)
            # Authenticate as end-user domain admin and verify that we have
            # appropriate access.
            client = u.authenticate_keystone(
                self.keystone_sentries[0].info['public-address'],
                username='admin',
                password='openstack',
                api_version=3,
                admin_port=True,
                user_domain_name='admin_domain',
                project_domain_name='admin_domain',
                project_name='admin',
            )

            try:
                client.domains.list()
                u.log.debug('OK')
            except Exception as e:
                message = ('Retrieve domain list as admin with project scoped '
                           'token FAILED. ({})'.format(e))
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_138_service_catalog(self):
        """Verify that the service catalog endpoint data is valid."""
        u.log.debug('Checking keystone service catalog...')
        self.set_api_version(2)
        endpoint_check = {
            'adminURL': u.valid_url,
            'id': u.not_null,
            'region': 'RegionOne',
            'publicURL': u.valid_url,
            'internalURL': u.valid_url
        }
        expected = {
            'volume': [endpoint_check],
            'identity': [endpoint_check]
        }
        actual = self.keystone_v2.service_catalog.get_endpoints()

        ret = u.validate_svc_catalog_endpoint_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_140_keystone_endpoint(self):
        """Verify the keystone endpoint data."""
        u.log.debug('Checking keystone api endpoint data...')
        endpoints = self.keystone_v2.endpoints.list()
        admin_port = '35357'
        internal_port = public_port = '5000'
        expected = {
            'id': u.not_null,
            'region': 'RegionOne',
            'adminurl': u.valid_url,
            'internalurl': u.valid_url,
            'publicurl': u.valid_url,
            'service_id': u.not_null
        }
        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            amulet.raise_status(amulet.FAIL,
                                msg='keystone endpoint: {}'.format(ret))

    def test_142_cinder_endpoint(self):
        """Verify the cinder endpoint data."""
        u.log.debug('Checking cinder endpoint...')
        endpoints = self.keystone_v2.endpoints.list()
        admin_port = internal_port = public_port = '8776'
        expected = {
            'id': u.not_null,
            'region': 'RegionOne',
            'adminurl': u.valid_url,
            'internalurl': u.valid_url,
            'publicurl': u.valid_url,
            'service_id': u.not_null
        }

        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            amulet.raise_status(amulet.FAIL,
                                msg='cinder endpoint: {}'.format(ret))

    def test_200_keystone_mysql_shared_db_relation(self):
        """Verify the keystone shared-db relation data"""
        u.log.debug('Checking keystone to mysql db relation data...')
        relation = ['shared-db', 'percona-cluster:shared-db']
        expected = {
            'username': 'keystone',
            'private-address': u.valid_ip,
            'hostname': u.valid_ip,
            'database': 'keystone'
        }
        for unit in self.keystone_sentries:
            ret = u.validate_relation_data(unit, relation, expected)
            if ret:
                message = u.relation_error('keystone shared-db', ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_201_mysql_keystone_shared_db_relation(self):
        """Verify the mysql shared-db relation data"""
        u.log.debug('Checking mysql to keystone db relation data...')
        unit = self.pxc_sentry
        relation = ['shared-db', 'keystone:shared-db']
        expected_data = {
            'private-address': u.valid_ip,
            'password': u.not_null,
            'db_host': u.valid_ip
        }
        ret = u.validate_relation_data(unit, relation, expected_data)
        if ret:
            message = u.relation_error('mysql shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_202_keystone_cinder_identity_service_relation(self):
        """Verify the keystone identity-service relation data"""
        u.log.debug('Checking keystone to cinder id relation data...')
        relation = ['identity-service', 'cinder:identity-service']
        expected = {
            'service_protocol': 'http',
            'service_tenant': 'services',
            'admin_token': 'ubuntutesting',
            'service_password': u.not_null,
            'service_port': '5000',
            'auth_port': '35357',
            'auth_protocol': 'http',
            'private-address': u.valid_ip,
            'auth_host': u.valid_ip,
            'service_username': 'cinder_cinderv2',
            'service_tenant_id': u.not_null,
            'service_host': u.valid_ip
        }
        for unit in self.keystone_sentries:
            ret = u.validate_relation_data(unit, relation, expected)
            if ret:
                message = u.relation_error('keystone identity-service', ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_203_cinder_keystone_identity_service_relation(self):
        """Verify the cinder identity-service relation data"""
        u.log.debug('Checking cinder to keystone id relation data...')
        unit = self.cinder_sentry
        relation = ['identity-service', 'keystone:identity-service']
        expected = {
            'cinder_service': 'cinder',
            'cinder_region': 'RegionOne',
            'cinder_public_url': u.valid_url,
            'cinder_internal_url': u.valid_url,
            'cinder_admin_url': u.valid_url,
            'cinderv2_service': 'cinderv2',
            'cinderv2_region': 'RegionOne',
            'cinderv2_public_url': u.valid_url,
            'cinderv2_internal_url': u.valid_url,
            'cinderv2_admin_url': u.valid_url,
            'private-address': u.valid_ip,
        }
        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('cinder identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_300_keystone_default_config(self):
        """Verify the data in the keystone config file,
           comparing some of the variables vs relation data."""
        u.log.debug('Checking keystone config file...')
        conf = '/etc/keystone/keystone.conf'
        ks_ci_rel = self.keystone_sentries[0].relation(
            'identity-service',
            'cinder:identity-service')
        my_ks_rel = self.pxc_sentry.relation('shared-db',
                                             'keystone:shared-db')
        db_uri = "mysql://{}:{}@{}/{}".format('keystone',
                                              my_ks_rel['password'],
                                              my_ks_rel['db_host'],
                                              'keystone')
        expected = {
            'DEFAULT': {
                'debug': 'False',
                'admin_token': ks_ci_rel['admin_token'],
                'use_syslog': 'False',
                'log_config_append': '/etc/keystone/logging.conf',
                'public_endpoint': u.valid_url,  # get specific
                'admin_endpoint': u.valid_url,  # get specific
            },
            'extra_headers': {
                'Distribution': 'Ubuntu'
            },
            'database': {
                'connection': db_uri,
                'idle_timeout': '200'
            }
        }

        if self._get_openstack_release() < self.trusty_mitaka:
            expected['DEFAULT']['verbose'] = 'False'
            expected['DEFAULT']['log_config'] = \
                expected['DEFAULT']['log_config_append']
            del expected['DEFAULT']['log_config_append']

        if self._get_openstack_release() >= self.trusty_kilo and \
           self._get_openstack_release() < self.trusty_mitaka:
            # Kilo and Liberty
            expected['eventlet_server'] = {
                'admin_bind_host': '0.0.0.0',
                'public_bind_host': '0.0.0.0',
                'admin_port': '35347',
                'public_port': '4990',
            }
        elif self._get_openstack_release() <= self.trusty_icehouse:
            # Juno and earlier
            expected['DEFAULT'].update({
                'admin_port': '35347',
                'public_port': '4990',
                'bind_host': '0.0.0.0',
            })

        for unit in self.keystone_sentries:
            for section, pairs in expected.iteritems():
                ret = u.validate_config_data(unit, conf, section, pairs)
                if ret:
                    message = "keystone config error: {}".format(ret)
                    amulet.raise_status(amulet.FAIL, msg=message)

    def test_301_keystone_default_policy(self):
        """Verify the data in the keystone policy.json file,
           comparing some of the variables vs relation data."""
        if not self.is_liberty_or_newer():
            return
        u.log.debug('Checking keystone v3 policy.json file')
        self.set_api_version(3)
        conf = '/etc/keystone/policy.json'
        ks_ci_rel = self.keystone_sentries[0].relation(
            'identity-service',
            'cinder:identity-service')
        if self._get_openstack_release() >= self.xenial_ocata:
            expected = {
                'admin_required': 'role:Admin',
                'cloud_admin':
                    'rule:admin_required and '
                    '(is_admin_project:True or '
                    'domain_id:{admin_domain_id} or '
                    'project_id:{service_tenant_id})'.format(
                        admin_domain_id=ks_ci_rel['admin_domain_id'],
                        service_tenant_id=ks_ci_rel['service_tenant_id']),
            }
        elif self._get_openstack_release() >= self.trusty_mitaka:
            expected = {
                'admin_required': 'role:Admin',
                'cloud_admin':
                    'rule:admin_required and '
                    '(token.is_admin_project:True or '
                    'domain_id:{admin_domain_id} or '
                    'project_id:{service_tenant_id})'.format(
                        admin_domain_id=ks_ci_rel['admin_domain_id'],
                        service_tenant_id=ks_ci_rel['service_tenant_id']),
            }
        else:
            expected = {
                'admin_required': 'role:Admin',
                'cloud_admin':
                    'rule:admin_required and '
                    'domain_id:{admin_domain_id}'.format(
                        admin_domain_id=ks_ci_rel['admin_domain_id']),
            }

        for unit in self.keystone_sentries:
            data = json.loads(unit.file_contents(conf))
            ret = u._validate_dict_data(expected, data)
            if ret:
                message = "keystone policy.json error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

        u.log.debug('OK')

    def test_302_keystone_logging_config(self):
        """Verify the data in the keystone logging config file"""
        u.log.debug('Checking keystone config file...')
        conf = '/etc/keystone/logging.conf'
        expected = {
            'logger_root': {
                'level': 'WARNING',
                'handlers': 'file,production',
            },
            'handlers': {
                'keys': 'production,file,devel'
            },
            'handler_file': {
                'level': 'DEBUG',
                'args': "('/var/log/keystone/keystone.log', 'a')"
            }
        }

        for unit in self.keystone_sentries:
            for section, pairs in expected.iteritems():
                ret = u.validate_config_data(unit, conf, section, pairs)
                if ret:
                    message = "keystone logging config error: {}".format(ret)
                    amulet.raise_status(amulet.FAIL, msg=message)

    def test_900_keystone_restart_on_config_change(self):
        """Verify that the specified services are restarted when the config
           is changed."""
        sentry = self.keystone_sentries[0]
        juju_service = 'keystone'

        # Expected default and alternate values
        set_default = {'use-syslog': 'False'}
        set_alternate = {'use-syslog': 'True'}

        # Services which are expected to restart upon config change,
        # and corresponding config files affected by the change
        if self.is_liberty_or_newer():
            services = {'apache2': '/etc/keystone/keystone.conf'}
        else:
            services = {'keystone-all': '/etc/keystone/keystone.conf'}
        # Make config change, check for service restarts
        u.log.debug('Making config change on {}...'.format(juju_service))
        mtime = u.get_sentry_time(sentry)
        self.d.configure(juju_service, set_alternate)

        sleep_time = 30
        for s, conf_file in services.iteritems():
            u.log.debug("Checking that service restarted: {}".format(s))
            if not u.validate_service_config_changed(sentry, mtime, s,
                                                     conf_file,
                                                     sleep_time=sleep_time):

                self.d.configure(juju_service, set_default)
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)

        self.d.configure(juju_service, set_default)

        u.log.debug('OK')

    def test_901_pause_resume(self):
        """Test pause and resume actions.

           NOTE: Toggle setting when service is paused to check config-changed
                 hook respects pause Bug #1648016
        """
        # Expected default and alternate values
        set_default = {'use-syslog': 'False'}
        set_alternate = {'use-syslog': 'True'}
        self._assert_services(should_run=True)
        for unit in self.keystone_sentries:
            action_id = u.run_action(unit, "pause")
            assert u.wait_on_action(action_id), "Pause action failed."

        self._assert_services(should_run=False)
        self.d.configure('keystone', set_alternate)
        for unit in self.keystone_sentries:
            action_id = u.run_action(unit, "resume")
            assert u.wait_on_action(action_id), "Resume action failed"
        self._assert_services(should_run=True)
        self.d.configure('keystone', set_default)
        self._auto_wait_for_status(message="Unit is ready",
                                   include_only=['keystone'])

    def test_910_test_user_password_reset(self):
        """Test that the admin v3 users password is set during
        shared-db-relation-changed. Bug #1644606

        NOTE: The amulet tests setup v2 and v3 credentials which means
              that the troublesome update_user_password executes cleanly but
              updates the v2 admin user in error. So, to catch this bug change
              the admin password and ensure that it is changed back when
              shared-db-relation-changed hook runs.
        """
        # NOTE(dosaboy): skipping this test so that we can land fix for
        #                LP: #1648677. Currently, if the admin password is
        #                changed outside the charm e.g. cli, the charm has no
        #                way to detect or retreive that password. The user
        #                would not need to update the admin-password config
        #                option to fix this.
        return

        if self.is_liberty_or_newer():
            timeout = int(os.environ.get('AMULET_SETUP_TIMEOUT', 900))
            self.set_api_version(3)
            self._auto_wait_for_status(
                message="Unit is ready",
                timeout=timeout,
                include_only=['keystone'])
            domain = self.keystone_v3.domains.find(name='admin_domain')
            v3_admin_user = self.keystone_v3.users.list(domain=domain)[0]
            u.log.debug(v3_admin_user)
            self.keystone_v3.users.update(user=v3_admin_user,
                                          password='wrongpass')
            u.log.debug('Removing keystone percona-cluster relation')
            self.d.unrelate('keystone:shared-db', 'percona-cluster:shared-db')
            self.d.sentry.wait(timeout=timeout)
            u.log.debug('Adding keystone percona-cluster relation')
            self.d.sentry.wait(timeout=timeout)
            self.d.relate('keystone:shared-db', 'percona-cluster:shared-db')
            self.set_api_version(3)
            self._auto_wait_for_status(
                message="Unit is ready",
                timeout=timeout,
                include_only=['keystone'])
            re_auth = u.authenticate_keystone_admin(
                self.keystone_sentries[0],
                user='admin',
                password='openstack',
                api_version=3,
                keystone_ip=self.keystone_ip)
            try:
                re_auth.users.list()
            except ksauth1_exceptions.http.Unauthorized:
                amulet.raise_status(
                    amulet.FAIL,
                    msg="Admin user password not reset")
            u.log.debug('OK')
