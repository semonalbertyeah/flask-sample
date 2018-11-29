# -*- coding:utf-8 -*-

from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base, DeclarativeMeta


##################################
# expire_on_commit=False
#   we need to use cached records after session.commit
##################################
Session = sessionmaker(expire_on_commit=False)
ThreadSession = scoped_session(Session)


# Base for all mappings.
class Meta(DeclarativeMeta):
    """
        Custom metaclass.
        Forwarding calling to some special methods to mapping class.
        (as calling class or static methods)
    """
    def __getitem__(cls, key):
        return cls.__getitem__(key)

    def __setitem__(cls, key, value):
        return cls.__setitem__(key, value)


class BaseTemp(object):
    def to_dict(self):
        # return {c.name: getattr(self, c.name) for c in self.__table__.columns}
        d = {}
        for c in self.__table__.columns:
            val = getattr(self, c.name)
            if hasattr(val, "scalar"):  # scalar method, return the scalar value of object.
                val = val.scalar()
            d[c.name] = val

        return d

Base = declarative_base(cls=BaseTemp, metaclass=Meta)



