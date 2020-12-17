from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, \
     ForeignKey, event
from sqlalchemy.orm import scoped_session, sessionmaker, backref, relation
from sqlalchemy.ext.declarative import declarative_base

from werkzeug import cached_property, http_date

from flask import url_for, Markup

db_parameters = {
    'USERNAME': 'root',
    'PASSWORD': 'password',
    'DATABASE': 'qualys_data'
}
DATABASE_URI = "postgresql://{USERNAME}:{PASSWORD}@localhost:5432/{DATABASE}".format(**db_parameters)

engine = create_engine(DATABASE_URI,
                       convert_unicode=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))

def init_db():
    Model.metadata.create_all(bind=engine)


Model = declarative_base(name='Model')
Model.query = db_session.query_property()



class VulnInfo(Model):
    __tablename__ = 'vuln_info'
    qid = Column('qid', Integer, primary_key=True)
    type = Column('type', String)
    severity = Column('severity', String)
    port = Column('port', String)
    protocol = Column('protocol', String)
    ssl = Column('ssl', String)
    results = Column('results', String)
    status = Column('status', String)
    first_found_datetime = Column('first_found_datetime', String)
    last_found_datetime = Column('last_found_datetime', String)
    times_found = Column('times_found', String)
    last_test_datetime = Column('last_test_datetime', String)
    last_update_datetime = Column('last_update_datetime', String)
    is_ignored = Column('is_ignored', String)
    is_disabled = Column('is_disabled', String)
    last_processed_datetime = Column('last_processed_datetime', String)

    def __init__(self, **kargs):
        self.qid = kargs.get('qid')
        self.type = kargs.get('type', None)
        self.severity = kargs.get('severity', None)
        self.port = kargs.get('port', None)
        self.protocol = kargs.get('protocol', None)
        self.ssl = kargs.get('ssl', None)
        self.results = kargs.get('results', None)
        self.status = kargs.get('status', None)
        self.first_found_datetime = kargs.get('first_found_datetime', None)
        self.last_found_datetime = kargs.get('last_found_datetime', None)
        self.times_found = kargs.get('times_found', None)
        self.last_test_datetime = kargs.get('last_test_datetime', None)
        self.last_update_datetime = kargs.get('last_update_datetime', None)
        self.is_ignored = kargs.get('is_ignored', None)
        self.is_disabled = kargs.get('is_disabled', None)
        self.last_processed_datetime = kargs.get('last_processed_datetime', None)

    def to_json(self):
        return dict(
            qid=self.qid,
            type=self.type,
            severity=self.severity,
            port=self.port,
            protocol=self.protocol,
            ssl=self.ssl,
            results=self.results,
            status=self.status,
            first_found_datetime=self.first_found_datetime,
            last_found_datetime=self.last_found_datetime,
            times_found=self.times_found,
            last_test_datetime=self.last_test_datetime,
            last_update_datetime=self.last_update_datetime,
            is_ignored=self.is_ignored,
            is_disabled=self.is_disabled,
            last_processed_datetime=self.last_processed_datetime,
        )

    def __eq__(self, other):
        return type(self) is type(other) and self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)


class HostInfo(Model):
    __tablename__ = 'user_info'
    id = Column('id', Integer, primary_key=True)
    ip = Column('ip', String)
    tracking_method = Column('tracking_method', String)
    name = Column('name', String)
    tracking_method = Column('tracking_method', String)
    dns = Column('dns', String)
    netbios = Column('netbios', String)
    os = Column('os', String)
    last_vuln_scan_datetime = Column('last_vuln_scan_datetime', String)
    last_vm_scanned_date = Column('last_vm_scanned_date', String)
    last_vm_scanned_duration = Column('last_vm_scanned_duration', String)
    last_vm_auth_scanned_date = Column('last_vm_auth_scanned_date', String)
    last_vm_auth_scanned_duration = Column('last_vm_auth_scanned_duration', String)
    
    def __init__(self, **kargs):
        self.id = kargs.get('id')
        self.ip = kargs.get('ip', None)
        self.tracking_method = kargs.get('tracking_method', None)
        self.name = kargs.get('name', None)
        self.tracking_method = kargs.get('tracking_method', None)
        self.dns = kargs.get('dns', None)
        self.netbios = kargs.get('netbios', None)
        self.os = kargs.get('os', None)
        self.last_vuln_scan_datetime = kargs.get('last_vuln_scan_datetime', None)
        self.last_vm_scanned_date = kargs.get('last_vm_scanned_date', None)
        self.last_vm_scanned_duration = kargs.get('last_vm_scanned_duration', None)
        self.last_vm_auth_scanned_date = kargs.get('last_vm_auth_scanned_date', None)
        self.last_vm_auth_scanned_duration = kargs.get('last_vm_auth_scanned_duration', None)

    def to_json(self):
        return dict(
            id=self.id,
            ip=self.ip,
            tracking_method=self.tracking_method,
            name=self.name,
            tracking_method=self.tracking_method,
            dns=self.dns,
            netbios=self.netbios,
            os=self.os,
            last_vuln_scan_datetime=self.last_vuln_scan_datetime,
            last_vm_scanned_date=self.last_vm_scanned_date,
            last_vm_scanned_duration=self.last_vm_scanned_duration,
            last_vm_auth_scanned_date=self.last_vm_auth_scanned_date,
            last_vm_auth_scanned_duration=self.last_vm_auth_scanned_duration,
        )

    def __eq__(self, other):
        return type(self) is type(other) and self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)
