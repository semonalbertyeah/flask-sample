# -*- coding:utf-8 -*-

from sqlalchemy import (
    Column, String
)
from sqlalchemy.dialects.mysql import (
    TINYINT, SMALLINT, MEDIUMINT,
    INTEGER, BIGINT
)

from .common import Base, ThreadSession
from .types import NamedIntEnum



class AlarmLog(Base):
    """
        alarm log
    """

    __tablename__ = 'alarmlog'

    id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    date = Column(INTEGER(unsigned=True)) # utc timestamp
    lvl_enum = {'warning': 0, 'alarm': 1, 'fatal': 2}
    lvl = Column(NamedIntEnum(enums=lvl_enum))
    msg = Column(String(500))


