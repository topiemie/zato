# -*- coding: utf-8 -*-

"""
Copyright (C) 2010 Dariusz Suchojad <dsuch at gefira.pl>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

# stdlib
from ftplib import FTP_PORT
from json import dumps

# SQLAlchemy
from sqlalchemy import MetaData, Sequence, UniqueConstraint, Enum

# Elixir
from elixir import Boolean, Entity, EntityBase, EntityMeta, DateTime, Field, \
     Integer, LargeBinary, ManyToOne, OneToMany, OneToOne, SmallInteger, \
     Unicode, using_options, using_table_options
from elixir.ext.versioned import acts_as_versioned

# Zato
from zato.common.util import make_repr, object_attrs
from zato.common.odb import AMQP_DEFAULT_PRIORITY, S3_DEFAULT_KEY_SYNC_TIMEOUT, \
     S3_DEFAULT_SEPARATOR, WMQ_DEFAULT_PRIORITY

class _ZatoBase(EntityBase):
    """ A base class for all Zato entities.
    """
    __metaclass__ = EntityMeta
    
    # Unfortunately, we can't use acts_as_versioned() in the base class.
    
    # Each entity stores information regarding who exactly made its last update.
    update_auth_ctx = Field(Unicode(6000), nullable=False, deferred=True, server_default='zzz')

    # Most entities can be de-/activated, meaning they will no longer be
    # available for use even though their definition will still be stored
    # in the ODB.
    is_active = Field(Boolean(), nullable=False, server_default='1')
    
    # Pretty much any entity can be one of Zato's internal built-ins.
    is_internal = Field(Boolean(), nullable=False, server_default='1')

################################################################################

'''
def to_json(model):
    """ Returns a JSON representation of an SQLAlchemy-backed object.
    """
    json = {}
    json['fields'] = {}
    json['pk'] = getattr(model, 'id')

    for col in model._sa_class_manager.mapper.mapped_table.columns:
        json['fields'][col.name] = getattr(model, col.name)

    return dumps([json])
'''

'''
class ZatoInstallState(Base):
    """ Contains a row for each Zato installation belonging to that particular
    ODB. For instance, installing Zato 1.0 will add a new row, installing 1.1
    """
    __tablename__ = 'install_state'

    id = Column(Integer,  Sequence('install_state_seq'), primary_key=True)
    version = Column(String(200), unique=True, nullable=False)
    install_time = Column(DateTime(), nullable=False)
    source_host = Column(String(200), nullable=False)
    source_user = Column(String(200), nullable=False)

    def __init__(self, id=None, version=None, install_time=None, source_host=None,
                 source_user=None):
        self.id = id
        self.version = version
        self.install_time = install_time
        self.source_host = source_host
        self.source_user = source_user
'''

class Cluster(_ZatoBase):
    """ Represents a Zato cluster.
    """
    acts_as_versioned()
    using_options(tablename='cluster')
    
    name = Field(Unicode(200), unique=True, nullable=False)
    description = Field(Unicode(1000), nullable=True)
    odb_type = Field(Unicode(30), nullable=False)
    odb_host = Field(Unicode(200), nullable=False)
    odb_port = Field(Integer(), nullable=False)
    odb_user = Field(Unicode(200), nullable=False)
    odb_db_name = Field(Unicode(200), nullable=False)
    odb_schema = Field(Unicode(200), nullable=True)
    broker_host = Field(Unicode(200), nullable=False)
    broker_start_port = Field(Integer(), nullable=False)
    broker_token = Field(Unicode(32), nullable=False)
    lb_host = Field(Unicode(200), nullable=False)
    lb_agent_port = Field(Integer(), nullable=False)
    lb_port = Field(Integer(), nullable=False)
    
    http_soap_list = OneToMany('HTTPSOAP')
    server_list = OneToMany('Server')
    service_list = OneToMany('Service')
    job_list = OneToMany('Job')
    conn_def_amqp_list = OneToMany('ConnDefAMQP')
    conn_def_wmq_list = OneToMany('ConnDefWMQ')
    out_ftp_list = OneToMany('OutgoingFTP')
    out_zmq_list = OneToMany('OutgoingZMQ')
    channel_zmq_list = OneToMany('ChannelZMQ')

class Server(_ZatoBase):
    """ Represents a Zato server.
    """
    acts_as_versioned()
    using_options(tablename='server')
    
    name = Field(Unicode(200), unique=True, nullable=False)
    last_join_status = Field(Unicode(40), nullable=False)
    last_join_mod_date = Field(DateTime(timezone=True), nullable=False)
    last_join_mod_by = Field(Unicode(200), nullable=False)
    
    odb_token = Field(Unicode(32), nullable=False)
    
    deployed_service_list = OneToMany('DeployedService')
    cluster = ManyToOne('Cluster', required=True)

################################################################################

class HTTPSOAPSecurity(_ZatoBase):
    """ A base class for any concrete HTTP-related authentication methods.
    """
    acts_as_versioned()
    using_options(inheritance='multi', tablename='http_sec')
    using_table_options(UniqueConstraint('name', 'cluster_id'))
    
    name = Field(Unicode(200), nullable=False)
    
    http_soap_list = OneToMany('HTTPSOAP')
    cluster = ManyToOne('Cluster', required=True)
    
class BasicAuth(HTTPSOAPSecurity):
    acts_as_versioned()
    using_options(inheritance='multi', tablename='basic_auth')
    
    update_auth_ctx = Field(Unicode(2000), nullable=False)
    username = Field(Unicode(200), nullable=False)
    domain = Field(Unicode(200), nullable=False)
    password = Field(Unicode(200), nullable=False)
    
class WSSDefinition(HTTPSOAPSecurity):
    """ A WS-Security definition.
    """
    acts_as_versioned()
    using_options(inheritance='multi', tablename='wss_def')
    
    update_auth_ctx = Field(Unicode(2000), nullable=False)
    username = Field(Unicode(200), nullable=False)
    domain = Field(Unicode(200), nullable=False)
    password = Field(Unicode(200), nullable=False)
    password_type = Field(Unicode(45), nullable=False)
    reject_empty_nonce_ts = Field(Boolean(), nullable=False)
    reject_stale_username = Field(Boolean(), nullable=False)
    expiry_limit = Field(Integer(), nullable=False)
    nonce_freshness = Field(Integer(), nullable=True)
    
    # To make autocompletion work
    password_type_raw = None # Not used by the DB
    
class TechnicalAccount(HTTPSOAPSecurity):
    acts_as_versioned()
    using_options(inheritance='multi', tablename='tech_acc')
    
    password = Field(Unicode(64), nullable=False)
    salt = Field(Unicode(32), nullable=False)
    
################################################################################


class HTTPSOAP(_ZatoBase):
    """ An incoming or outgoing HTTP/SOAP connection.
    """
    acts_as_versioned()
    using_options(tablename='http_soap')
    using_table_options(UniqueConstraint('name', 'connection', 'cluster_id'),
                         UniqueConstraint('url_path', 'connection', 'soap_action', 'cluster_id'))
                         
    name = Field(Unicode(200), nullable=False)
    connection = Field(Unicode(20), nullable=False) # Channel or outgoing
    transport = Field(Unicode(20), nullable=False) # HTTP or SOAP
     
    url_path = Field(Unicode(200), nullable=False)
    method = Field(Unicode(200), nullable=True)
     
    soap_action = Field(Unicode(200), nullable=True)
    soap_version = Field(Unicode(20), nullable=True)
    
    security = ManyToOne('HTTPSOAPSecurity', required=True)
    cluster = ManyToOne('Cluster', required=True)
    service = ManyToOne('Service', required=True)
    
    # To make autocompletion work
    service_name = None # Not used by the DB
    security_id = None # Not used by the DB
    security_name = None # Not used by the DB


################################################################################

class SQLConnectionPool(_ZatoBase):
    """ An SQL connection pool.
    """
    acts_as_versioned()
    using_options(tablename='sql_pool')
    using_table_options(UniqueConstraint('name', 'cluster_id'))

    name = Field(Unicode(200), nullable=False)
    engine = Field(Unicode(200), nullable=False)
    host = Field(Unicode(200), nullable=False)
    port = Field(Integer(), nullable=False)
    db_name = Field(Unicode(200), nullable=False)
    user = Field(Unicode(200), nullable=False)
    password = Field(Unicode(200), nullable=False)
    pool_size = Field(Integer(), nullable=False)
    extra = Field(LargeBinary(200000), nullable=True, deferred=True)
    
    cluster = ManyToOne('Cluster', required=True)

################################################################################

class Service(_ZatoBase):
    """ A set of basic informations about a service available in a given cluster.
    """
    acts_as_versioned()
    using_options(tablename='service')
    using_table_options(UniqueConstraint('name', 'cluster_id'))
    
    name = Field(Unicode(2000), nullable=False)
    impl_name = Field(Unicode(2000), nullable=False)
    
    cluster = ManyToOne('Cluster', required=True)
    deployed_list = OneToMany('DeployedService')
    job_list = OneToMany('Job')
    channel_amqp_list = OneToMany('ChannelAMQP')
    channel_wmq_list = OneToMany('ChannelWMQ')
    channel_zmq_list = OneToMany('ChannelZMQ')

class DeployedService(_ZatoBase):
    """ A service deployed to a server.
    """
    acts_as_versioned()
    using_options(tablename='deployed_service')
    deployment_time = Field(DateTime(timezone=True), nullable=False)
    details = Field(Unicode(4000), nullable=False)
    
    server = ManyToOne('Server', required=True)
    service = ManyToOne('Service', required=True)

class Job(_ZatoBase):
    """ A scheduler's job. Stores all the information needed to execute a job
    if it's a one-time job, otherwise the information is kept in other tables.
    """
    acts_as_versioned()
    using_options(inheritance='multi', tablename='job')
    using_table_options(UniqueConstraint('name', 'cluster_id'))
    
    name = Field(Unicode(200), nullable=False)
    job_type = Field(Enum('one_time', 'interval_based', 'cron_style', name='job_type'))
    start_date = Field(DateTime(timezone=True), nullable=False)
    extra = Field(LargeBinary(400000), nullable=True, deferred=True)

    cluster = ManyToOne('Cluster', required=True)
    service = ManyToOne('Service', required=True)
    
    # To make autocompletion work
    service_name = None # Not used by the database
    definition_text = None # Not used by the database
    job_type_friendly = None # Not used by the database
    
class IntervalBasedJob(Job):
    """ An interval-based job.
    """
    acts_as_versioned()
    using_options(inheritance='multi', tablename='job_interval_based')
    
    update_auth_ctx = Field(Unicode(2000), nullable=False)
    weeks = Field(Integer(), nullable=True)
    days = Field(Integer(), nullable=True)
    hours = Field(Integer(), nullable=True)
    minutes = Field(Integer(), nullable=True)
    seconds = Field(Integer(), nullable=True)
    repeats = Field(Integer(), nullable=True)
    
    # To make autocompletion work
    definition_text = None # Not used by the database
    
class CronStyleJob(Job):
    """ A Cron-style scheduler's job.
    """
    acts_as_versioned()
    using_options(inheritance='multi', tablename='job_cron_style')
    
    update_auth_ctx = Field(Unicode(2000), nullable=False)
    cron_definition = Field(Unicode(4000), nullable=False)

################################################################################

class ConnDefAMQP(_ZatoBase):
    """ An AMQP connection definition.
    """
    acts_as_versioned()
    using_options(tablename='conn_def_amqp')
    using_table_options(UniqueConstraint('name', 'cluster_id', 'def_type'))

    name = Field(Unicode(200), nullable=False)
    def_type = Field(Unicode(10), nullable=False)

    host = Field(Unicode(200), nullable=False)
    port = Field(Integer(), nullable=False)
    vhost = Field(Unicode(200), nullable=False)
    username = Field(Unicode(200), nullable=False)
    password = Field(Unicode(200), nullable=False)
    frame_max = Field(Integer(), nullable=False)
    heartbeat = Field(Integer(), nullable=False)
    
    cluster = ManyToOne('Cluster', required=True)
    out_list = OneToMany('OutgoingAMQP')

class ConnDefWMQ(_ZatoBase):
    """ A WebSphere MQ connection definition.
    """
    acts_as_versioned()
    using_options(tablename='conn_def_wmq')
    using_table_options(UniqueConstraint('name', 'cluster_id'))
    
    name = Field(Unicode(200), nullable=False)
    
    host = Field(Unicode(200), nullable=False)
    port = Field(Integer(), nullable=False)
    
    queue_manager = Field(Unicode(200), nullable=False)
    channel = Field(Unicode(200), nullable=False)
    cache_open_send_queues = Field(Boolean(), nullable=False)
    cache_open_receive_queues = Field(Boolean(), nullable=False)
    use_shared_connections = Field(Boolean(), nullable=False)
    dynamic_queue_template = Field(Unicode(200), nullable=False, server_default='SYSTEM.DEFAULT.MODEL.QUEUE') # We're not actually using it yet
    ssl = Field(Boolean(), nullable=False)
    ssl_cipher_spec = Field(Unicode(200), nullable=False)
    ssl_key_repository = Field(Unicode(200), nullable=False)
    needs_mcd = Field(Boolean(), nullable=False)
    max_chars_printed = Field(Integer(), nullable=False)
    
    cluster = ManyToOne('Cluster', required=True)
    out_list = OneToMany('OutgoingWMQ')

class OutgoingAMQP(_ZatoBase):
    """ An outgoing AMQP connection.
    """
    acts_as_versioned()
    using_options(tablename='out_amqp')
    using_table_options(UniqueConstraint('name', 'def_id'))
    
    name = Field(Unicode(200), nullable=False)
    
    delivery_mode = Field(SmallInteger(), nullable=False)
    priority = Field(SmallInteger(), server_default=str(AMQP_DEFAULT_PRIORITY), nullable=False)
    
    content_type = Field(Unicode(200), nullable=True)
    content_encoding = Field(Unicode(200), nullable=True)
    expiration = Field(Unicode(20), nullable=True)
    user_id = Field(Unicode(200), nullable=True)
    app_id = Field(Unicode(200), nullable=True)
    
    def_ = ManyToOne('ConnDefAMQP', required=True, colname='def_id')

class OutgoingFTP(_ZatoBase):
    """ An outgoing FTP connection.
    """
    acts_as_versioned()
    using_options(tablename='out_ftp')
    using_table_options(UniqueConstraint('name', 'cluster_id'))
    
    name = Field(Unicode(200), nullable=False)
    host = Field(Unicode(200), nullable=False)
    port = Field(Integer(), nullable=False, server_default=str(FTP_PORT))
    user = Field(Unicode(200), nullable=True)
    password = Field(Unicode(200), nullable=True)
    acct = Field(Unicode(200), nullable=True)
    timeout = Field(Integer(), nullable=True)
    dircache = Field(Boolean(), nullable=False)
    
    cluster = ManyToOne('Cluster', required=True)
    
class OutgoingS3(_ZatoBase):
    """ An outgoing FTP connection.
    """
    acts_as_versioned()
    using_options(tablename='out_s3')
    using_table_options(UniqueConstraint('name', 'cluster_id'))
    
    name = Field(Unicode(200), nullable=False)
    prefix = Field(Unicode(200), nullable=False)
    separator = Field(Unicode(20), nullable=False, server_default=str(S3_DEFAULT_SEPARATOR))
    key_sync_timeout = Field(Integer(), nullable=False, server_default=str(S3_DEFAULT_KEY_SYNC_TIMEOUT),)
    
    cluster = ManyToOne('Cluster', required=True)
    
class OutgoingWMQ(_ZatoBase):
    """ An outgoing WebSphere MQ connection.
    """
    acts_as_versioned()
    using_options(tablename='out_wmq')
    using_table_options(UniqueConstraint('name', 'def_id'))
    
    name = Field(Unicode(200), nullable=False)
    
    delivery_mode = Field(SmallInteger(), nullable=False)
    priority = Field(SmallInteger(), server_default=str(WMQ_DEFAULT_PRIORITY), nullable=False)
    expiration = Field(Unicode(20), nullable=True)
    
    def_ = ManyToOne('ConnDefWMQ', required=True, colname='def_id')
    
class OutgoingZMQ(_ZatoBase):
    """ An outgoing Zero MQ connection.
    """
    acts_as_versioned()
    using_options(tablename='out_zmq')
    using_table_options(UniqueConstraint('name', 'cluster_id'))
    
    name = Field(Unicode(200), nullable=False)
    address = Field(Unicode(200), nullable=False)
    socket_type = Field(Unicode(20), nullable=False)
    
    cluster = ManyToOne('Cluster', required=True)
    
class ChannelAMQP(_ZatoBase):
    """ An incoming AMQP connection.
    """
    acts_as_versioned()
    using_options(tablename='channel_amqp')
    using_table_options(UniqueConstraint('name', 'def_id'))
    
    name = Field(Unicode(200), nullable=False)
    queue = Field(Unicode(200), nullable=False)
    consumer_tag_prefix = Field(Unicode(200), nullable=False)
    
    def_ = ManyToOne('ConnDefAMQP', required=True, colname='def_id')
    service = ManyToOne('Service', required=True)
    
class ChannelWMQ(_ZatoBase):
    """ An incoming WebSphere MQ connection.
    """
    acts_as_versioned()
    using_options(tablename='channel_wmq')
    using_table_options(UniqueConstraint('name', 'def_id'))
    
    name = Field(Unicode(200), nullable=False)
    queue = Field(Unicode(200), nullable=False)
    
    def_ = ManyToOne('ConnDefWMQ', required=True, colname='def_id')
    service = ManyToOne('Service', required=True)
    
    # To make autocompletion work
    def_name = None # Not used by the DB
    service_name = None # Not used by the DB
    
class ChannelZMQ(_ZatoBase):
    """ An incoming Zero MQ connection.
    """
    acts_as_versioned()
    using_options(tablename='channel_zmq')
    using_table_options(UniqueConstraint('name', 'cluster_id'))
    
    name = Field(Unicode(200), nullable=False)
    address = Field(Unicode(200), nullable=False)
    socket_type = Field(Unicode(20), nullable=False)
    sub_key = Field(Unicode(200), nullable=True)
    
    service = ManyToOne('Service', required=True)
    cluster = ManyToOne('Cluster', required=True)
    
################################################################################
