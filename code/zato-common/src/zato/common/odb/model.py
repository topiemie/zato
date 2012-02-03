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
from sqlalchemy import Table, Column, Integer, String, DateTime, MetaData, \
     ForeignKey, Sequence, Boolean, LargeBinary, UniqueConstraint, Enum, \
     SmallInteger
from sqlalchemy.ext.declarative import ConcreteBase, declarative_base
from sqlalchemy.orm import backref, relationship

# Elixir
from elixir import Boolean, Entity, DateTime, Field, Integer, ManyToOne, OneToMany, \
     Unicode, using_options, using_table_options
from elixir.ext.versioned import acts_as_versioned

# Zato
from zato.common.util import make_repr, object_attrs
from zato.common.odb import AMQP_DEFAULT_PRIORITY, S3_DEFAULT_KEY_SYNC_TIMEOUT, \
     S3_DEFAULT_SEPARATOR, WMQ_DEFAULT_PRIORITY

Base = declarative_base()

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

class Cluster(Entity):
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
    odb_schema = Field(Unicode(200), nullable=False)
    broker_host = Field(Unicode(200), nullable=False)
    broker_start_port = Field(Integer(), nullable=False)
    broker_token = Field(Unicode(32), nullable=False)
    lb_host = Field(Unicode(200), nullable=False)
    lb_agent_port = Field(Integer(), nullable=False)
    lb_port = Field(Integer(), nullable=False)
    update_auth_ctx = Field(Unicode(2000), nullable=False)
    
    server_list = OneToMany('Server')
    http_soap_list = OneToMany('HTTPSOAP')

class Server(Entity):
    """ Represents a Zato server.
    """
    acts_as_versioned()
    using_options(tablename='server')
    
    update_auth_ctx = Field(Unicode(2000), nullable=False)
    name = Field(Unicode(200), unique=True, nullable=False)
    
    last_join_status = Field(Unicode(40), nullable=False)
    last_join_mod_date = Field(DateTime(timezone=True), nullable=False)
    last_join_mod_by = Column(String(200), nullable=False)
    
    odb_token = Field(Unicode(32), nullable=False)
    update_auth_ctx = Field(Unicode(2000), nullable=False)
    
    cluster = ManyToOne('Cluster', required=True)


################################################################################

class HTTPSOAPSecurity(Entity):
    """ A base class for any concrete HTTP-related authentication methods.
    """
    acts_as_versioned()
    using_options(inheritance='multi', tablename='http_sec')
    using_table_options(UniqueConstraint('name', 'cluster_id'))
    
    name = Field(Unicode(200), nullable=False)
    is_active = Field(Boolean(), nullable=False)
    
    http_soap_list = OneToMany('HTTPSOAP')
    cluster = ManyToOne('Cluster', required=True)
    
class BasicAuth(HTTPSOAPSecurity):
    acts_as_versioned()
    using_options(inheritance='multi', tablename='basic_auth')
    
    username = Field(Unicode(200), nullable=False)
    domain = Field(Unicode(200), nullable=False)
    password = Field(Unicode(200), nullable=False)
    
class WSSDefinition(HTTPSOAPSecurity):
    """ A WS-Security definition.
    """
    acts_as_versioned()
    using_options(inheritance='multi', tablename='wss_def')
    
    username = Field(Unicode(200), nullable=False)
    domain = Field(Unicode(200), nullable=False)
    password = Field(Unicode(200), nullable=False)
    password_type = Field(Unicode(45), nullable=False)
    reject_empty_nonce_ts = Field(Boolean(), nullable=False)
    reject_stale_username = Field(Boolean(), nullable=False)
    expiry_limit = Field(Integer(), nullable=False)
    nonce_freshness = Field(Integer(), nullable=True)
    
    # To make autocompletion work.
    password_type_raw = None # Not used by the DB
    
################################################################################


class HTTPSOAP(Entity):
    """ An incoming or outgoing HTTP/SOAP connection.
    """
    acts_as_versioned()
    using_options(tablename='http_soap')
    using_table_options(UniqueConstraint('name', 'connection', 'cluster_id'),
                         UniqueConstraint('url_path', 'connection', 'soap_action', 'cluster_id'))
                         
    name = Field(Unicode(200), nullable=False)
    is_active = Field(Boolean(), nullable=False)
    is_internal = Field(Boolean(), nullable=False)
    
    connection = Field(Unicode(20), nullable=False) # Channel or outgoing
    transport = Field(Unicode(20), nullable=False) # HTTP or SOAP
     
    url_path = Field(Unicode(200), nullable=False)
    method = Field(Unicode(200), nullable=False)
     
    soap_action = Field(Unicode(200), nullable=True)
    soap_version = Field(Unicode(20), nullable=True)
    
    security = ManyToOne('HTTPSOAPSecurity', required=True)
    cluster = ManyToOne('Cluster', required=True)
    
    # To make autocompletion work.
    service_name = None # Not used by the DB
    security_id = None # Not used by the DB
    security_name = None # Not used by the DB


'''
    
class TechnicalAccount(Base):
    """ Stores information about technical accounts, used for instance by Zato
    itself for securing access to its API.
    """
    __tablename__ = 'tech_account'
    __table_args__ = (UniqueConstraint('name'), {})
    __mapper_args__ = {'polymorphic_identity':'tech_acc', 'concrete':True}

    id = Column(Integer,  Sequence('tech_account_id_seq'), primary_key=True)
    name = Column(String(45), nullable=False)
    is_active = Column(Boolean(), nullable=False)
    password = Column(String(64), nullable=False)
    salt = Column(String(32), nullable=False)
    
    sec_type = Column(String(45), nullable=False)

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('tech_accounts', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, password=None, 
                 salt=None, sec_type=None, cluster=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.password = password
        self.salt = salt
        self.sec_type = sec_type
        self.cluster = cluster

    def to_json(self):
        return to_json(self)

################################################################################
'''

'''
class SQLConnectionPool(Base):
    """ An SQL connection pool.
    """
    __tablename__ = 'sql_pool'
    __table_args__ = (UniqueConstraint('cluster_id', 'name'), {})

    id = Column(Integer,  Sequence('sql_pool_id_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    user = Column(String(200), nullable=False)
    db_name = Column(String(200), nullable=False)
    engine = Column(String(200), nullable=False)
    extra = Column(LargeBinary(200000), nullable=True)
    host = Column(String(200), nullable=False)
    port = Column(Integer(), nullable=False)
    pool_size = Column(Integer(), nullable=False)

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('sql_pools', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, db_name=None, user=None, engine=None,
                 extra=None, host=None, port=None, pool_size=None, cluster=None):
        self.id = id
        self.name = name
        self.db_name = db_name
        self.user = user
        self.engine = engine
        self.extra = extra
        self.host = host
        self.port = port
        self.pool_size = pool_size
        self.cluster = cluster

    def __repr__(self):
        return make_repr(self)

class SQLConnectionPoolPassword(Base):
    """ An SQL connection pool's passwords.
    """
    __tablename__ = 'sql_pool_passwd'

    id = Column(Integer,  Sequence('sql_pool_id_seq'), primary_key=True)
    password = Column(LargeBinary(200000), server_default='not-set-yet', nullable=False)
    server_key_hash = Column(LargeBinary(200000), server_default='not-set-yet', nullable=False)

    server_id = Column(Integer, ForeignKey('server.id', ondelete='CASCADE'), nullable=False)
    server = relationship(Server, backref=backref('sql_pool_passwords', order_by=id, cascade='all, delete, delete-orphan'))

    sql_pool_id = Column(Integer, ForeignKey('sql_pool.id', ondelete='CASCADE'), nullable=False)
    sql_pool = relationship(SQLConnectionPool, backref=backref('sql_pool_passwords', order_by=id, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, password=None, server_key_hash=None, server_id=None,
                 server=None, sql_pool_id=None, sql_pool=None):
        self.id = id
        self.password = password
        self.server_key_hash = server_key_hash
        self.server_id = server_id
        self.server = server
        self.sql_pool_id = sql_pool_id
        self.sql_pool = sql_pool

    def __repr__(self):
        return make_repr(self)


################################################################################
'''




'''
class Service(Base):
    """ A set of basic informations about a service available in a given cluster.
    """
    __tablename__ = 'service'
    __table_args__ = (UniqueConstraint('name', 'cluster_id'), {})

    id = Column(Integer,  Sequence('service_id_seq'), primary_key=True)
    name = Column(String(2000), nullable=False)
    is_active = Column(Boolean(), nullable=False)
    impl_name = Column(String(2000), nullable=False)
    is_internal = Column(Boolean(), nullable=False)

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('services', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, impl_name=None, 
                 is_internal=None, cluster=None, usage_count=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.impl_name = impl_name
        self.is_internal = is_internal
        self.cluster = cluster
        self.usage_count = usage_count # Not used by the database

class DeployedService(Base):
    """ A service living on a given server.
    """
    __tablename__ = 'deployed_service'
    __table_args__ = (UniqueConstraint('server_id', 'service_id'), {})

    deployment_time = Column(DateTime(), nullable=False)
    details = Column(String(2000), nullable=False)

    server_id = Column(Integer, ForeignKey('server.id', ondelete='CASCADE'), nullable=False, primary_key=True)
    server = relationship(Server, backref=backref('deployed_services', order_by=deployment_time, cascade='all, delete, delete-orphan'))

    service_id = Column(Integer, ForeignKey('service.id', ondelete='CASCADE'), nullable=False, primary_key=True)
    service = relationship(Service, backref=backref('deployment_data', order_by=deployment_time, cascade='all, delete, delete-orphan'))

    def __init__(self, deployment_time, details, server, service):
        self.deployment_time = deployment_time
        self.details = details
        self.server = server
        self.service = service

################################################################################

class Job(Base):
    """ A scheduler's job. Stores all the information needed to execute a job
    if it's a one-time job, otherwise the information is kept in related tables.
    """
    __tablename__ = 'job'
    __table_args__ = (UniqueConstraint('name', 'cluster_id'), {})

    id = Column(Integer,  Sequence('job_id_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean(), nullable=False)
    job_type = Column(Enum('one_time', 'interval_based', 'cron_style',
                           name='job_type'), nullable=False)
    start_date = Column(DateTime(), nullable=False)
    extra = Column(LargeBinary(400000), nullable=True)

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('jobs', order_by=name, cascade='all, delete, delete-orphan'))

    service_id = Column(Integer, ForeignKey('service.id', ondelete='CASCADE'), nullable=False)
    service = relationship(Service, backref=backref('jobs', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, job_type=None,
                 start_date=None, extra=None, cluster=None, cluster_id=None,
                 service=None, service_id=None, service_name=None, interval_based=None,
                 cron_style=None, definition_text=None, job_type_friendly=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.job_type = job_type
        self.start_date = start_date
        self.extra = extra
        self.cluster = cluster
        self.cluster_id = cluster_id
        self.service = service
        self.service_id = service_id
        self.service_name = service_name # Not used by the database
        self.interval_based = interval_based
        self.cron_style = cron_style
        self.definition_text = definition_text # Not used by the database
        self.job_type_friendly = job_type_friendly # Not used by the database

class IntervalBasedJob(Base):
    """ A Cron-style scheduler's job.
    """
    __tablename__ = 'job_interval_based'
    __table_args__ = (UniqueConstraint('job_id'), {})

    id = Column(Integer,  Sequence('job_intrvl_seq'), primary_key=True)
    job_id = Column(Integer, nullable=False)

    weeks = Column(Integer, nullable=True)
    days = Column(Integer, nullable=True)
    hours = Column(Integer, nullable=True)
    minutes = Column(Integer, nullable=True)
    seconds = Column(Integer, nullable=True)
    repeats = Column(Integer, nullable=True)

    job_id = Column(Integer, ForeignKey('job.id', ondelete='CASCADE'), nullable=False)
    job = relationship(Job, backref=backref('interval_based', uselist=False, cascade='all, delete, delete-orphan', single_parent=True))

    def __init__(self, id=None, job=None, weeks=None, days=None, hours=None,
                 minutes=None, seconds=None, repeats=None, definition_text=None):
        self.id = id
        self.job = job
        self.weeks = weeks
        self.days = days
        self.hours = hours
        self.minutes = minutes
        self.seconds = seconds
        self.repeats = repeats
        self.definition_text = definition_text # Not used by the database

class CronStyleJob(Base):
    """ A Cron-style scheduler's job.
    """
    __tablename__ = 'job_cron_style'
    __table_args__ = (UniqueConstraint('job_id'), {})

    id = Column(Integer,  Sequence('job_cron_seq'), primary_key=True)
    cron_definition = Column(String(4000), nullable=False)

    job_id = Column(Integer, ForeignKey('job.id', ondelete='CASCADE'), nullable=False)
    job = relationship(Job, backref=backref('cron_style', uselist=False, cascade='all, delete, delete-orphan', single_parent=True))

    def __init__(self, id=None, job=None, cron_definition=None):
        self.id = id
        self.job = job
        self.cron_definition = cron_definition

################################################################################

class ConnDefAMQP(Base):
    """ An AMQP connection definition.
    """
    __tablename__ = 'conn_def_amqp'
    __table_args__ = (UniqueConstraint('name', 'cluster_id', 'def_type'), {})

    id = Column(Integer,  Sequence('conn_def_amqp_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    def_type = Column(String(10), nullable=False)

    host = Column(String(200), nullable=False)
    port = Column(Integer(), nullable=False)
    vhost = Column(String(200), nullable=False)
    username = Column(String(200), nullable=False)
    password = Column(String(200), nullable=False)
    frame_max = Column(Integer(), nullable=False)
    heartbeat = Column(Integer(), nullable=False)

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('amqp_conn_defs', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, def_type=None, host=None, port=None,
                 vhost=None,  username=None,  password=None, frame_max=None,
                 heartbeat=None, cluster_id=None):
        self.id = id
        self.name = name
        self.def_type = def_type
        self.host = host
        self.port = port
        self.vhost = vhost
        self.username = username
        self.password = password
        self.frame_max = frame_max
        self.heartbeat = heartbeat
        self.cluster_id = cluster_id

class ConnDefWMQ(Base):
    """ A WebSphere MQ connection definition.
    """
    __tablename__ = 'conn_def_wmq'
    __table_args__ = (UniqueConstraint('name', 'cluster_id'), {})

    id = Column(Integer,  Sequence('conn_def_wmq_seq'), primary_key=True)
    name = Column(String(200), nullable=False)

    host = Column(String(200), nullable=False)
    port = Column(Integer, nullable=False)
    queue_manager = Column(String(200), nullable=False)
    channel = Column(String(200), nullable=False)
    cache_open_send_queues = Column(Boolean(), nullable=False)
    cache_open_receive_queues = Column(Boolean(), nullable=False)
    use_shared_connections = Column(Boolean(), nullable=False)
    dynamic_queue_template = Column(String(200), nullable=False, server_default='SYSTEM.DEFAULT.MODEL.QUEUE') # We're not actually using it yet
    ssl = Column(Boolean(), nullable=False)
    ssl_cipher_spec = Column(String(200))
    ssl_key_repository = Column(String(200))
    needs_mcd = Column(Boolean(), nullable=False)
    max_chars_printed = Column(Integer, nullable=False)

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('wmq_conn_defs', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, host=None, port=None,
                 queue_manager=None, channel=None, cache_open_send_queues=None,
                 cache_open_receive_queues=None,  use_shared_connections=None, ssl=None,
                 ssl_cipher_spec=None, ssl_key_repository=None, needs_mcd=None,
                 max_chars_printed=None, cluster_id=None):
        self.id = id
        self.name = name
        self.host = host
        self.queue_manager = queue_manager
        self.channel = channel
        self.port = port
        self.cache_open_receive_queues = cache_open_receive_queues
        self.cache_open_send_queues = cache_open_send_queues
        self.use_shared_connections = use_shared_connections
        self.ssl = ssl
        self.ssl_cipher_spec = ssl_cipher_spec
        self.ssl_key_repository = ssl_key_repository
        self.needs_mcd = needs_mcd
        self.max_chars_printed = max_chars_printed
        self.cluster_id = cluster_id

################################################################################

class OutgoingAMQP(Base):
    """ An outgoing AMQP connection.
    """
    __tablename__ = 'out_amqp'
    __table_args__ = (UniqueConstraint('name', 'def_id'), {})

    id = Column(Integer,  Sequence('out_amqp_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean(), nullable=False)

    delivery_mode = Column(SmallInteger(), nullable=False)
    priority = Column(SmallInteger(), server_default=str(AMQP_DEFAULT_PRIORITY), nullable=False)

    content_type = Column(String(200), nullable=True)
    content_encoding = Column(String(200), nullable=True)
    expiration = Column(String(20), nullable=True)
    user_id = Column(String(200), nullable=True)
    app_id = Column(String(200), nullable=True)

    def_id = Column(Integer, ForeignKey('conn_def_amqp.id', ondelete='CASCADE'), nullable=False)
    def_ = relationship(ConnDefAMQP, backref=backref('out_conns_amqp', cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, delivery_mode=None,
                 priority=None, content_type=None, content_encoding=None,
                 expiration=None, user_id=None, app_id=None, def_id=None,
                 delivery_mode_text=None, def_name=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.delivery_mode = delivery_mode
        self.priority = priority
        self.content_type = content_type
        self.content_encoding = content_encoding
        self.expiration = expiration
        self.user_id = user_id
        self.app_id = app_id
        self.def_id = def_id
        self.delivery_mode_text = delivery_mode_text # Not used by the DB
        self.def_name = def_name # Not used by the DB
        
class OutgoingFTP(Base):
    """ An outgoing FTP connection.
    """
    __tablename__ = 'out_ftp'
    __table_args__ = (UniqueConstraint('name', 'cluster_id'), {})

    id = Column(Integer,  Sequence('out_ftp_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean(), nullable=False)

    host = Column(String(200), nullable=False)
    user = Column(String(200), nullable=True)
    password = Column(String(200), nullable=True)
    acct = Column(String(200), nullable=True)
    timeout = Column(Integer, nullable=True)
    port = Column(Integer, server_default=str(FTP_PORT), nullable=False)
    dircache = Column(Boolean(), nullable=False)

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('out_conns_ftp', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, host=None, user=None, 
                 password=None, acct=None, timeout=None, port=None, dircache=None,
                 cluster_id=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.host = host
        self.user = user
        self.password = password
        self.acct = acct
        self.timeout = timeout
        self.port = port
        self.dircache = dircache
        self.cluster_id = cluster_id

class OutgoingS3(Base):
    """ An outgoing S3 connection.
    """
    __tablename__ = 'out_s3'
    __table_args__ = (UniqueConstraint('name', 'cluster_id'), {})

    id = Column(Integer,  Sequence('out_s3_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean(), nullable=False)

    prefix = Column(String(200), nullable=False)
    separator = Column(String(20), server_default=str(S3_DEFAULT_SEPARATOR), nullable=False)
    key_sync_timeout = Column(Integer, server_default=str(S3_DEFAULT_KEY_SYNC_TIMEOUT), nullable=False)

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('out_conns_s3', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, prefix=None,
                 separator=None, key_sync_timeout=None, cluster_id=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.prefix = prefix
        self.separator = separator
        self.key_sync_timeout = key_sync_timeout
        self.cluster_id = cluster_id
        
class OutgoingWMQ(Base):
    """ An outgoing WebSphere MQ connection.
    """
    __tablename__ = 'out_wmq'
    __table_args__ = (UniqueConstraint('name', 'def_id'), {})

    id = Column(Integer,  Sequence('out_wmq_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean(), nullable=False)

    delivery_mode = Column(SmallInteger(), nullable=False)
    priority = Column(SmallInteger(), server_default=str(WMQ_DEFAULT_PRIORITY), nullable=False)
    expiration = Column(String(20), nullable=True)

    def_id = Column(Integer, ForeignKey('conn_def_wmq.id', ondelete='CASCADE'), nullable=False)
    def_ = relationship(ConnDefWMQ, backref=backref('out_conns_wmq', cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, delivery_mode=None,
                 priority=None, expiration=None, def_id=None, delivery_mode_text=None,
                 def_name=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.delivery_mode = delivery_mode
        self.priority = priority
        self.expiration = expiration
        self.def_id = def_id
        self.delivery_mode_text = delivery_mode_text # Not used by the DB
        self.def_name = def_name # Not used by the DB

class OutgoingZMQ(Base):
    """ An outgoing Zero MQ connection.
    """
    __tablename__ = 'out_zmq'
    __table_args__ = (UniqueConstraint('name', 'cluster_id'), {})

    id = Column(Integer,  Sequence('out_zmq_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean(), nullable=False)

    address = Column(String(200), nullable=False)
    socket_type = Column(String(20), nullable=False)

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('out_conns_zmq', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, address=None,
                 socket_type=None, cluster_id=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.socket_type = socket_type
        self.address = address
        self.cluster_id = cluster_id

################################################################################

class ChannelAMQP(Base):
    """ An incoming AMQP connection.
    """
    __tablename__ = 'channel_amqp'
    __table_args__ = (UniqueConstraint('name', 'def_id'), {})

    id = Column(Integer,  Sequence('channel_amqp_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean(), nullable=False)
    queue = Column(String(200), nullable=False)
    consumer_tag_prefix = Column(String(200), nullable=False)

    service_id = Column(Integer, ForeignKey('service.id', ondelete='CASCADE'), nullable=False)
    service = relationship(Service, backref=backref('channels_amqp', order_by=name, cascade='all, delete, delete-orphan'))

    def_id = Column(Integer, ForeignKey('conn_def_amqp.id', ondelete='CASCADE'), nullable=False)
    def_ = relationship(ConnDefAMQP, backref=backref('channels_amqp', cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, queue=None,
                 consumer_tag_prefix=None, def_id=None, def_name=None,
                 service_name=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.queue = queue
        self.consumer_tag_prefix = consumer_tag_prefix
        self.def_id = def_id
        self.def_name = def_name # Not used by the DB
        self.service_name = service_name # Not used by the DB

class ChannelWMQ(Base):
    """ An incoming WebSphere MQ connection.
    """
    __tablename__ = 'channel_wmq'
    __table_args__ = (UniqueConstraint('name', 'def_id'), {})

    id = Column(Integer,  Sequence('channel_wmq_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean(), nullable=False)
    queue = Column(String(200), nullable=False)

    service_id = Column(Integer, ForeignKey('service.id', ondelete='CASCADE'), nullable=False)
    service = relationship(Service, backref=backref('channels_wmq', order_by=name, cascade='all, delete, delete-orphan'))

    def_id = Column(Integer, ForeignKey('conn_def_wmq.id', ondelete='CASCADE'), nullable=False)
    def_ = relationship(ConnDefWMQ, backref=backref('channels_wmq', cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, queue=None,
                 def_id=None, def_name=None, service_name=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.queue = queue
        self.def_id = def_id
        self.def_name = def_name # Not used by the DB
        self.service_name = service_name # Not used by the DB

class ChannelZMQ(Base):
    """ An incoming Zero MQ connection.
    """
    __tablename__ = 'channel_zmq'
    __table_args__ = (UniqueConstraint('name', 'cluster_id'), {})

    id = Column(Integer,  Sequence('channel_zmq_seq'), primary_key=True)
    name = Column(String(200), nullable=False)
    is_active = Column(Boolean(), nullable=False)

    address = Column(String(200), nullable=False)
    socket_type = Column(String(20), nullable=False)
    sub_key = Column(String(200), nullable=True)
    
    service_id = Column(Integer, ForeignKey('service.id', ondelete='CASCADE'), nullable=False)
    service = relationship(Service, backref=backref('channels_zmq', order_by=name, cascade='all, delete, delete-orphan'))

    cluster_id = Column(Integer, ForeignKey('cluster.id', ondelete='CASCADE'), nullable=False)
    cluster = relationship(Cluster, backref=backref('channels_zmq', order_by=name, cascade='all, delete, delete-orphan'))

    def __init__(self, id=None, name=None, is_active=None, address=None,
                 socket_type=None, sub_key=None, service_name=None):
        self.id = id
        self.name = name
        self.is_active = is_active
        self.address = address
        self.socket_type = socket_type
        self.sub_key = sub_key
        self.service_name = service_name # Not used by the DB
'''