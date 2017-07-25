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

import hashlib
import json
import os
import sys

from subprocess import check_call

from charmhelpers.contrib import unison
from charmhelpers.core import unitdata

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    is_relation_made,
    log,
    local_unit,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    relation_get,
    relation_ids,
    relation_set,
    related_units,
    status_set,
    open_port,
    is_leader,
)

from charmhelpers.core.host import (
    mkdir,
    service_pause,
    service_restart,
)

from charmhelpers.core.strutils import (
    bool_from_string,
)

from charmhelpers.fetch import (
    apt_install, apt_update,
    filter_installed_packages
)

from charmhelpers.contrib.openstack.utils import (
    config_value_changed,
    configure_installation_source,
    git_install_requested,
    openstack_upgrade_available,
    sync_db_with_multi_ipv6_addresses,
    os_release,
    pausable_restart_on_change as restart_on_change,
    is_unit_paused_set,
    CompareOpenStackReleases,
)

from keystone_utils import (
    add_service_to_keystone,
    add_credentials_to_keystone,
    determine_packages,
    disable_unused_apache_sites,
    do_openstack_upgrade_reexec,
    ensure_initial_admin,
    get_admin_passwd,
    git_install,
    migrate_database,
    save_script_rc,
    synchronize_ca_if_changed,
    register_configs,
    restart_map,
    services,
    CLUSTER_RES,
    KEYSTONE_CONF,
    POLICY_JSON,
    TOKEN_FLUSH_CRON_FILE,
    SSH_USER,
    setup_ipv6,
    send_notifications,
    check_peer_actions,
    get_ssl_sync_request_units,
    is_ssl_cert_master,
    is_db_ready,
    clear_ssl_synced_units,
    is_db_initialised,
    update_certs_if_available,
    ensure_ssl_dir,
    ensure_pki_dir_permissions,
    ensure_permissions,
    force_ssl_sync,
    filter_null,
    ensure_ssl_dirs,
    ensure_pki_cert_paths,
    is_service_present,
    delete_service_entry,
    assess_status,
    run_in_apache,
    restart_function_map,
    WSGI_KEYSTONE_API_CONF,
    restart_pid_check,
    get_api_version,
    ADMIN_DOMAIN,
    ADMIN_PROJECT,
    create_or_show_domain,
    keystone_service,
)

from charmhelpers.contrib.hahelpers.cluster import (
    is_elected_leader,
    get_hacluster_config,
    peer_units,
    https,
    is_clustered,
)

from charmhelpers.contrib.openstack.ha.utils import (
    update_dns_ha_resource_params,
    expect_ha,
)

from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.peerstorage import (
    peer_retrieve_by_prefix,
    peer_echo,
)
from charmhelpers.contrib.openstack.ip import (
    ADMIN,
    resolve_address,
)
from charmhelpers.contrib.network.ip import (
    get_iface_for_address,
    get_netmask_for_address,
    is_ipv6,
    get_relation_ip,
)
from charmhelpers.contrib.openstack.context import ADDRESS_TYPES

from charmhelpers.contrib.charmsupport import nrpe

from charmhelpers.contrib.hardening.harden import harden

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook('install.real')
@harden()
def install():
    status_set('maintenance', 'Executing pre-install')
    execd_preinstall()
    configure_installation_source(config('openstack-origin'))
    status_set('maintenance', 'Installing apt packages')
    apt_update()
    apt_install(determine_packages(), fatal=True)
    if run_in_apache():
        disable_unused_apache_sites()
        if not git_install_requested():
            service_pause('keystone')

    status_set('maintenance', 'Git install')
    git_install(config('openstack-origin-git'))

    unison.ensure_user(user=SSH_USER, group='juju_keystone')
    unison.ensure_user(user=SSH_USER, group='keystone')


@hooks.hook('config-changed')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
@synchronize_ca_if_changed(fatal=True)
@harden()
def config_changed():
    if config('prefer-ipv6'):
        status_set('maintenance', 'configuring ipv6')
        setup_ipv6()
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'))

    unison.ensure_user(user=SSH_USER, group='juju_keystone')
    unison.ensure_user(user=SSH_USER, group='keystone')
    homedir = unison.get_homedir(SSH_USER)
    if not os.path.isdir(homedir):
        mkdir(homedir, SSH_USER, 'juju_keystone', 0o775)

    if git_install_requested():
        if config_value_changed('openstack-origin-git'):
            status_set('maintenance', 'Running Git install')
            git_install(config('openstack-origin-git'))
    elif not config('action-managed-upgrade'):
        if openstack_upgrade_available('keystone'):
            status_set('maintenance', 'Running openstack upgrade')
            do_openstack_upgrade_reexec(configs=CONFIGS)

    for r_id in relation_ids('cluster'):
        cluster_joined(rid=r_id, ssl_sync_request=False)

    config_changed_postupgrade()


@hooks.hook('config-changed-postupgrade')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
@synchronize_ca_if_changed(fatal=True)
@harden()
def config_changed_postupgrade():
    # Ensure ssl dir exists and is unison-accessible
    ensure_ssl_dir()

    check_call(['chmod', '-R', 'g+wrx', '/var/lib/keystone/'])

    ensure_ssl_dirs()

    save_script_rc()
    if run_in_apache():
        # Need to ensure mod_wsgi is installed and apache2 is reloaded
        # immediatly as charm querys its local keystone before restart
        # decorator can fire
        apt_install(filter_installed_packages(determine_packages()))
        # when deployed from source, init scripts aren't installed
        if not git_install_requested():
            service_pause('keystone')
        disable_unused_apache_sites()
        CONFIGS.write(WSGI_KEYSTONE_API_CONF)
        if not is_unit_paused_set():
            restart_pid_check('apache2')
    configure_https()
    open_port(config('service-port'))

    update_nrpe_config()
    CONFIGS.write_all()

    initialise_pki()

    update_all_identity_relation_units()
    update_all_domain_backends()

    # Ensure sync request is sent out (needed for any/all ssl change)
    send_ssl_sync_request()

    for r_id in relation_ids('ha'):
        ha_joined(relation_id=r_id)


@synchronize_ca_if_changed(fatal=True)
def initialise_pki():
    """Create certs and keys required for token signing.

    Used for PKI and signing token revocation list.

    NOTE: keystone.conf [signing] section must be up-to-date prior to
          executing this.
    """
    if CompareOpenStackReleases(os_release('keystone-common')) >= 'pike':
        # pike dropped support for PKI token; skip function
        return
    ensure_pki_cert_paths()
    if not peer_units() or is_ssl_cert_master():
        log("Ensuring PKI token certs created", level=DEBUG)
        cmd = ['keystone-manage', 'pki_setup', '--keystone-user', 'keystone',
               '--keystone-group', 'keystone']
        check_call(cmd)

        # Ensure logfile has keystone perms since we may have just created it
        # with root.
        ensure_permissions('/var/log/keystone', user='keystone',
                           group='keystone', perms=0o744)
        ensure_permissions('/var/log/keystone/keystone.log', user='keystone',
                           group='keystone', perms=0o644)

    ensure_pki_dir_permissions()


@hooks.hook('shared-db-relation-joined')
def db_joined():
    if is_relation_made('pgsql-db'):
        # error, postgresql is used
        e = ('Attempting to associate a mysql database when there is already '
             'associated a postgresql one')
        log(e, level=ERROR)
        raise Exception(e)

    if config('prefer-ipv6'):
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'))
    else:
        # Avoid churn check for access-network early
        access_network = None
        for unit in related_units():
            access_network = relation_get(unit=unit,
                                          attribute='access-network')
            if access_network:
                break
        host = get_relation_ip('shared-db', cidr_network=access_network)

        relation_set(database=config('database'),
                     username=config('database-user'),
                     hostname=host)


@hooks.hook('pgsql-db-relation-joined')
def pgsql_db_joined():
    if is_relation_made('shared-db'):
        # raise error
        e = ('Attempting to associate a postgresql database when there'
             ' is already associated a mysql one')
        log(e, level=ERROR)
        raise Exception(e)

    relation_set(database=config('database'))


def update_all_identity_relation_units(check_db_ready=True):
    CONFIGS.write_all()
    if is_unit_paused_set():
        return
    if check_db_ready and not is_db_ready():
        log('Allowed_units list provided and this unit not present',
            level=INFO)
        return

    if not is_db_initialised():
        log("Database not yet initialised - deferring identity-relation "
            "updates", level=INFO)
        return

    if is_elected_leader(CLUSTER_RES):
        ensure_initial_admin(config)

    log('Firing identity_changed hook for all related services.')
    for rid in relation_ids('identity-service'):
        for unit in related_units(rid):
            identity_changed(relation_id=rid, remote_unit=unit)
    log('Firing admin_relation_changed hook for all related services.')
    for rid in relation_ids('identity-admin'):
        admin_relation_changed(rid)
    log('Firing identity_credentials_changed hook for all related services.')
    for rid in relation_ids('identity-credentials'):
        for unit in related_units(rid):
            identity_credentials_changed(relation_id=rid, remote_unit=unit)


@synchronize_ca_if_changed(force=True)
def update_all_identity_relation_units_force_sync():
    update_all_identity_relation_units()


def update_all_domain_backends():
    """Re-trigger hooks for all domain-backend relations/units"""
    for rid in relation_ids('domain-backend'):
        for unit in related_units(rid):
            domain_backend_changed(relation_id=rid, unit=unit)


def leader_init_db_if_ready(use_current_context=False):
    """ Initialise the keystone db if it is ready and mark it as initialised.

    NOTE: this must be idempotent.
    """
    if not is_elected_leader(CLUSTER_RES):
        log("Not leader - skipping db init", level=DEBUG)
        return

    if is_db_initialised():
        log("Database already initialised - skipping db init", level=DEBUG)
        update_all_identity_relation_units(check_db_ready=False)
        return

    # Bugs 1353135 & 1187508. Dbs can appear to be ready before the
    # units acl entry has been added. So, if the db supports passing
    # a list of permitted units then check if we're in the list.
    if not is_db_ready(use_current_context=use_current_context):
        log('Allowed_units list provided and this unit not present',
            level=INFO)
        return

    migrate_database()
    # Ensure any existing service entries are updated in the
    # new database backend. Also avoid duplicate db ready check.
    update_all_identity_relation_units(check_db_ready=False)
    update_all_domain_backends()


@hooks.hook('shared-db-relation-changed')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
@synchronize_ca_if_changed()
def db_changed():
    if 'shared-db' not in CONFIGS.complete_contexts():
        log('shared-db relation incomplete. Peer not ready?')
    else:
        CONFIGS.write(KEYSTONE_CONF)
        leader_init_db_if_ready(use_current_context=True)
        if CompareOpenStackReleases(
                os_release('keystone-common')) >= 'liberty':
            CONFIGS.write(POLICY_JSON)


@hooks.hook('pgsql-db-relation-changed')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
@synchronize_ca_if_changed()
def pgsql_db_changed():
    if 'pgsql-db' not in CONFIGS.complete_contexts():
        log('pgsql-db relation incomplete. Peer not ready?')
    else:
        CONFIGS.write(KEYSTONE_CONF)
        leader_init_db_if_ready(use_current_context=True)
        if CompareOpenStackReleases(
                os_release('keystone-common')) >= 'liberty':
            CONFIGS.write(POLICY_JSON)


@hooks.hook('identity-service-relation-changed')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
@synchronize_ca_if_changed()
def identity_changed(relation_id=None, remote_unit=None):
    CONFIGS.write_all()

    notifications = {}
    if is_elected_leader(CLUSTER_RES):
        if not is_db_ready():
            log("identity-service-relation-changed hook fired before db "
                "ready - deferring until db ready", level=WARNING)
            return

        if not is_db_initialised():
            log("Database not yet initialised - deferring identity-relation "
                "updates", level=INFO)
            return

        if expect_ha() and not is_clustered():
            log("Expected to be HA but no hacluster relation yet", level=INFO)
            return

        add_service_to_keystone(relation_id, remote_unit)
        if is_service_present('neutron', 'network'):
            delete_service_entry('quantum', 'network')
        settings = relation_get(rid=relation_id, unit=remote_unit)
        service = settings.get('service', None)
        if service:
            # If service is known and endpoint has changed, notify service if
            # it is related with notifications interface.
            csum = hashlib.sha256()
            # We base the decision to notify on whether these parameters have
            # changed (if csum is unchanged from previous notify, relation will
            # not fire).
            csum.update(settings.get('public_url', None))
            csum.update(settings.get('admin_url', None))
            csum.update(settings.get('internal_url', None))
            notifications['%s-endpoint-changed' % (service)] = csum.hexdigest()
    else:
        # Each unit needs to set the db information otherwise if the unit
        # with the info dies the settings die with it Bug# 1355848
        for rel_id in relation_ids('identity-service'):
            peerdb_settings = peer_retrieve_by_prefix(rel_id)
            # Ensure the null'd settings are unset in the relation.
            peerdb_settings = filter_null(peerdb_settings)
            if 'service_password' in peerdb_settings:
                relation_set(relation_id=rel_id, **peerdb_settings)

        log('Deferring identity_changed() to service leader.')

    if notifications:
        send_notifications(notifications)


@hooks.hook('identity-credentials-relation-joined',
            'identity-credentials-relation-changed')
def identity_credentials_changed(relation_id=None, remote_unit=None):
    """Update the identity credentials relation on change

    Calls add_credentials_to_keystone

    :param relation_id: Relation id of the relation
    :param remote_unit: Related unit on the relation
    """
    if is_elected_leader(CLUSTER_RES):
        if expect_ha() and not is_clustered():
            log("Expected to be HA but no hacluster relation yet", level=INFO)
            return
        if not is_db_ready():
            log("identity-credentials-relation-changed hook fired before db "
                "ready - deferring until db ready", level=WARNING)
            return

        if not is_db_initialised():
            log("Database not yet initialised - deferring "
                "identity-credentials-relation updates", level=INFO)
            return

        # Create the tenant user
        add_credentials_to_keystone(relation_id, remote_unit)
    else:
        log('Deferring identity_credentials_changed() to service leader.')


def send_ssl_sync_request():
    """Set sync request on cluster relation.

    Value set equals number of ssl configs currently enabled so that if they
    change, we ensure that certs are synced. This setting is consumed by
    cluster-relation-changed ssl master. We also clear the 'synced' set to
    guarantee that a sync will occur.

    Note the we do nothing if the setting is already applied.
    """
    unit = local_unit().replace('/', '-')
    # Start with core config (e.g. used for signing revoked token list)
    ssl_config = 0b1

    use_https = config('use-https')
    if use_https and bool_from_string(use_https):
        ssl_config ^= 0b10

    https_service_endpoints = config('https-service-endpoints')
    if (https_service_endpoints and
            bool_from_string(https_service_endpoints)):
        ssl_config ^= 0b100

    enable_pki = config('enable-pki')
    if enable_pki and bool_from_string(enable_pki):
        ssl_config ^= 0b1000

    key = 'ssl-sync-required-%s' % (unit)
    settings = {key: ssl_config}

    prev = 0b0
    rid = None
    for rid in relation_ids('cluster'):
        for unit in related_units(rid):
            _prev = relation_get(rid=rid, unit=unit, attribute=key) or 0b0
            if _prev and _prev > prev:
                prev = bin(_prev)

    if rid and prev ^ ssl_config:
        clear_ssl_synced_units()
        log("Setting %s=%s" % (key, bin(ssl_config)), level=DEBUG)
        relation_set(relation_id=rid, relation_settings=settings)


@hooks.hook('cluster-relation-joined')
def cluster_joined(rid=None, ssl_sync_request=True):
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='juju_keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)

    settings = {}

    for addr_type in ADDRESS_TYPES:
        address = get_relation_ip(
            addr_type,
            cidr_network=config('os-{}-network'.format(addr_type)))
        if address:
            settings['{}-address'.format(addr_type)] = address

    settings['private-address'] = get_relation_ip('cluster')

    relation_set(relation_id=rid, relation_settings=settings)

    if ssl_sync_request:
        send_ssl_sync_request()


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed')
@restart_on_change(restart_map(), stopstart=True)
@update_certs_if_available
def cluster_changed():
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='juju_keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)
    # NOTE(jamespage) re-echo passwords for peer storage
    echo_whitelist = ['_passwd', 'identity-service:', 'ssl-cert-master',
                      'db-initialised', 'ssl-cert-available-updates']
    log("Peer echo whitelist: %s" % (echo_whitelist), level=DEBUG)
    peer_echo(includes=echo_whitelist, force=True)

    check_peer_actions()

    initialise_pki()

    # Figure out if we need to mandate a sync
    units = get_ssl_sync_request_units()
    synced_units = relation_get(attribute='ssl-synced-units',
                                unit=local_unit())
    diff = None
    if synced_units:
        synced_units = json.loads(synced_units)
        diff = set(units).symmetric_difference(set(synced_units))

    if units and (not synced_units or diff):
        log("New peers joined and need syncing - %s" %
            (', '.join(units)), level=DEBUG)
        update_all_identity_relation_units_force_sync()
    else:
        update_all_identity_relation_units()

    if not is_elected_leader(CLUSTER_RES) and is_ssl_cert_master():
        # Force and sync and trigger a sync master re-election since we are not
        # leader anymore.
        force_ssl_sync()
    else:
        CONFIGS.write_all()


@hooks.hook('leader-elected')
def leader_elected():
    log('Unit has been elected leader.', level=DEBUG)
    # When the local unit has been elected the leader, update the cron jobs
    # to ensure that the cron jobs are active on this unit.
    CONFIGS.write(TOKEN_FLUSH_CRON_FILE)


@hooks.hook('leader-settings-changed')
def leader_settings_changed():
    # Since minions are notified of a regime change via the
    # leader-settings-changed hook, rewrite the token flush cron job to make
    # sure only the leader is running the cron job.
    CONFIGS.write(TOKEN_FLUSH_CRON_FILE)

    update_all_identity_relation_units()


@hooks.hook('ha-relation-joined')
def ha_joined(relation_id=None):
    cluster_config = get_hacluster_config()
    resources = {
        'res_ks_haproxy': 'lsb:haproxy',
    }
    resource_params = {
        'res_ks_haproxy': 'op monitor interval="5s"'
    }

    if config('dns-ha'):
        update_dns_ha_resource_params(relation_id=relation_id,
                                      resources=resources,
                                      resource_params=resource_params)
    else:
        vip_group = []
        for vip in cluster_config['vip'].split():
            if is_ipv6(vip):
                res_ks_vip = 'ocf:heartbeat:IPv6addr'
                vip_params = 'ipv6addr'
            else:
                res_ks_vip = 'ocf:heartbeat:IPaddr2'
                vip_params = 'ip'

            iface = (get_iface_for_address(vip) or
                     config('vip_iface'))
            netmask = (get_netmask_for_address(vip) or
                       config('vip_cidr'))

            if iface is not None:
                vip_key = 'res_ks_{}_vip'.format(iface)
                if vip_key in vip_group:
                    log("Resource '%s' (vip='%s') already exists in "
                        "vip group - skipping" % (vip_key, vip),
                        WARNING)
                    continue

                vip_group.append(vip_key)
                resources[vip_key] = res_ks_vip
                resource_params[vip_key] = (
                    'params {ip}="{vip}" cidr_netmask="{netmask}"'
                    ' nic="{iface}"'.format(ip=vip_params,
                                            vip=vip,
                                            iface=iface,
                                            netmask=netmask)
                )

        if len(vip_group) >= 1:
            relation_set(relation_id=relation_id,
                         groups={CLUSTER_RES: ' '.join(vip_group)})

    init_services = {
        'res_ks_haproxy': 'haproxy'
    }
    clones = {
        'cl_ks_haproxy': 'res_ks_haproxy'
    }
    relation_set(relation_id=relation_id,
                 init_services=init_services,
                 corosync_bindiface=cluster_config['ha-bindiface'],
                 corosync_mcastport=cluster_config['ha-mcastport'],
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones)


@hooks.hook('ha-relation-changed')
@restart_on_change(restart_map(), restart_functions=restart_function_map())
@synchronize_ca_if_changed()
def ha_changed():
    CONFIGS.write_all()

    clustered = relation_get('clustered')
    if clustered:
        log('Cluster configured, notifying other services and updating '
            'keystone endpoint configuration')
        update_all_identity_relation_units()


@hooks.hook('identity-admin-relation-changed')
def admin_relation_changed(relation_id=None):
    # TODO: fixup
    if expect_ha() and not is_clustered():
        log("Expected to be HA but no hacluster relation yet", level=INFO)
        return
    relation_data = {
        'service_hostname': resolve_address(ADMIN),
        'service_port': config('service-port'),
        'service_username': config('admin-user'),
        'service_tenant_name': config('admin-role'),
        'service_region': config('region'),
        'service_protocol': 'https' if https() else 'http',
        'api_version': get_api_version(),
    }
    if relation_data['api_version'] > 2:
        relation_data['service_user_domain_name'] = ADMIN_DOMAIN
        relation_data['service_project_domain_name'] = ADMIN_DOMAIN
        relation_data['service_project_name'] = ADMIN_PROJECT
    relation_data['service_password'] = get_admin_passwd()
    relation_set(relation_id=relation_id, **relation_data)


@hooks.hook('domain-backend-relation-changed')
def domain_backend_changed(relation_id=None, unit=None):
    if get_api_version() < 3:
        log('Domain specific backend identity configuration only supported '
            'with Keystone v3 API, skipping domain creation and '
            'restart.')
        return

    domain_name = relation_get(attribute='domain-name',
                               unit=unit,
                               rid=relation_id)
    if domain_name:
        # NOTE(jamespage): Only create domain data from lead
        #                  unit when clustered and database
        #                  is configured and created.
        if is_leader() and is_db_ready() and is_db_initialised():
            create_or_show_domain(domain_name)
        # NOTE(jamespage): Deployment may have multiple domains,
        #                  with different identity backends so
        #                  ensure that a domain specific nonce
        #                  is checked for restarts of keystone
        restart_nonce = relation_get(attribute='restart-nonce',
                                     unit=unit,
                                     rid=relation_id)
        domain_nonce_key = 'domain-restart-nonce-{}'.format(domain_name)
        db = unitdata.kv()
        if restart_nonce != db.get(domain_nonce_key):
            if not is_unit_paused_set():
                service_restart(keystone_service())
            db.set(domain_nonce_key, restart_nonce)
            db.flush()


@synchronize_ca_if_changed(fatal=True)
def configure_https():
    '''
    Enables SSL API Apache config if appropriate and kicks identity-service
    with any required api updates.
    '''
    # need to write all to ensure changes to the entire request pipeline
    # propagate (c-api, haprxy, apache)
    CONFIGS.write_all()
    if 'https' in CONFIGS.complete_contexts():
        cmd = ['a2ensite', 'openstack_https_frontend']
        check_call(cmd)
    else:
        cmd = ['a2dissite', 'openstack_https_frontend']
        check_call(cmd)


@hooks.hook('upgrade-charm')
@restart_on_change(restart_map(), stopstart=True)
@synchronize_ca_if_changed()
@harden()
def upgrade_charm():
    status_set('maintenance', 'Installing apt packages')
    apt_install(filter_installed_packages(determine_packages()))
    unison.ssh_authorized_peers(user=SSH_USER,
                                group='juju_keystone',
                                peer_interface='cluster',
                                ensure_local_user=True)

    ensure_ssl_dirs()

    if run_in_apache():
        disable_unused_apache_sites()

    CONFIGS.write_all()

    # See LP bug 1519035
    leader_init_db_if_ready()

    update_nrpe_config()

    if is_elected_leader(CLUSTER_RES):
        log('Cluster leader - ensuring endpoint configuration is up to '
            'date', level=DEBUG)
        update_all_identity_relation_units()


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.copy_nrpe_checks()
    nrpe.add_init_service_checks(nrpe_setup, services(), current_unit)
    nrpe.add_haproxy_checks(nrpe_setup, current_unit)
    nrpe_setup.write()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status(CONFIGS)


if __name__ == '__main__':
    main()
