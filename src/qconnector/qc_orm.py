from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, DateTime, \
     ForeignKey, event
from .qc_init import Model, engine, db_session
from datetime import datetime
from dateutil import parser, tz


def parse_dt(dt_str=None):
    if dt_str is None:
        return get_utc_now()
    return parser.parse(dt_str).replace(tzinfo=tz.tzutc())


def get_utc_now():
    return datetime.utcnow().replace(tzinfo=tz.tzutc())


def init_db():
    Model.metadata.create_all(bind=engine)


def create_vuln_info(hid, vuln_info):
    kargs = {'hid':hid}
    kargs.update(vuln_info)
    return VulnInfo.get(**kargs)

class VulnInfo(Model):
    __tablename__ = 'vuln_info'
    id = Column(String, primary_key=True)
    qid = Column('qid', Integer)
    hid = Column('qid', Integer)
    type = Column('type', String)
    severity = Column('severity', String)
    port = Column('port', String)
    protocol = Column('protocol', String)
    ssl = Column('ssl', String)
    results = Column('results', String)
    status = Column('status', String)
    first_found_datetime = Column('first_found_datetime', DateTime)
    last_found_datetime = Column('last_found_datetime', DateTime)
    times_found = Column('times_found', String)
    last_test_datetime = Column('last_test_datetime', DateTime)
    last_update_datetime = Column('last_update_datetime', DateTime)
    is_ignored = Column('is_ignored', String)
    is_disabled = Column('is_disabled', String)
    last_processed_datetime = Column('last_processed_datetime', DateTime)
    host_info_id = Column(Integer, ForeignKey('host_info.id'))
    host_info = relationship("HostInfo", back_populates="vuln_infos")

    def __init__(self, **kargs):
        self.hid = kargs.get('hid', None)
        self.qid = kargs.get('qid', None)
        self.id = '{}_{}'.format(self.hid, self.qid)
        self.type = kargs.get('type', None)
        self.severity = kargs.get('severity', None)
        self.port = kargs.get('port', None)
        self.protocol = kargs.get('protocol', None)
        self.ssl = kargs.get('ssl', None)
        self.results = kargs.get('results', None)
        self.status = kargs.get('status', None)
        self.first_found_datetime = parse_dt(kargs.get('first_found_datetime', None))
        self.last_found_datetime = parse_dt(kargs.get('last_found_datetime', None))
        self.times_found = parse_dt(kargs.get('times_found', None))
        self.last_test_datetime = parse_dt(kargs.get('last_test_datetime', None))
        self.last_update_datetime = parse_dt(kargs.get('last_update_datetime', None))
        self.is_ignored = kargs.get('is_ignored', None)
        self.is_disabled = kargs.get('is_disabled', None)
        self.last_processed_datetime = parse_dt(kargs.get('last_processed_datetime', None))

    def to_json(self):
        return dict(
            id=self.id,
            hid=self.hid,
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

    @classmethod
    def get(cls, **kargs):
        _id = kargs.get('id', None)
        if _id is None:
            hid = kargs.get('hid')
            qid = kargs.get('qid')
            _id = "{}_{}".format(hid, qid)

        if _id is not None:
            results = [i for i in db_session.query(VulnInfo).filter(VulnInfo.id == _id)]
            if len(results) > 0:
                return results[0]
        x = cls(**kargs)
        db_session.add(x)
        db_session.commit()
        return x

    def __eq__(self, other):
        return type(self) is type(other) and self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)


class HostInfo(Model):
    __tablename__ = 'host_info'
    id = Column('id', Integer, primary_key=True)
    ip = Column('ip', String)
    tracking_method = Column('tracking_method', String)
    name = Column('name', String)
    dns = Column('dns', String)
    netbios = Column('netbios', String)
    os = Column('os', String)
    last_vuln_scan_datetime = Column('last_vuln_scan_datetime', DateTime)
    last_vm_scanned_date = Column('last_vm_scanned_date', DateTime)
    last_vm_scanned_duration = Column('last_vm_scanned_duration', DateTime)
    last_vm_auth_scanned_date = Column('last_vm_auth_scanned_date', DateTime)
    last_vm_auth_scanned_duration = Column('last_vm_auth_scanned_duration', DateTime)
    # vuln_infos = relationship("VulnInfo", back_populates="host_info")
    vuln_infos = relationship("VulnInfo")
    
    def __init__(self, **kargs):
        self.id = kargs.get('id')
        self.ip = kargs.get('ip', None)
        self.tracking_method = kargs.get('tracking_method', None)
        self.name = kargs.get('name', None)
        self.tracking_method = kargs.get('tracking_method', None)
        self.dns = kargs.get('dns', None)
        self.netbios = kargs.get('netbios', None)
        self.os = kargs.get('os', None)
        self.last_vuln_scan_datetime = parse_dt(kargs.get('last_vuln_scan_datetime', None))
        self.last_vm_scanned_date = parse_dt(kargs.get('last_vm_scanned_date', None))
        self.last_vm_scanned_duration = parse_dt(kargs.get('last_vm_scanned_duration', None))
        self.last_vm_auth_scanned_date = parse_dt(kargs.get('last_vm_auth_scanned_date', None))
        self.last_vm_auth_scanned_duration = parse_dt(kargs.get('last_vm_auth_scanned_duration', None))

    def to_json(self):
        return dict(
            id=self.id,
            ip=self.ip,
            tracking_method=self.tracking_method,
            name=self.name,
            dns=self.dns,
            netbios=self.netbios,
            os=self.os,
            last_vuln_scan_datetime=self.last_vuln_scan_datetime,
            last_vm_scanned_date=self.last_vm_scanned_date,
            last_vm_scanned_duration=self.last_vm_scanned_duration,
            last_vm_auth_scanned_date=self.last_vm_auth_scanned_date,
            last_vm_auth_scanned_duration=self.last_vm_auth_scanned_duration,
        )

    @classmethod
    def get(cls, **kargs):
        _id = kargs.get('id', None)
        if _id is not None:
            results = [i for i in db_session.query(HostInfo).filter(HostInfo.id == _id)]
            if len(results) > 0:
                return results[0]
        x = cls(**kargs)
        db_session.add(x)
        db_session.commit()
        return x

    def add_vuln_info(self, vuln_info):
        self.vuln_infos.append(vuln_info)
        db_session.add(self)
        db_session.commit()

    def __eq__(self, other):
        return type(self) is type(other) and self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)

