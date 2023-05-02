from jupyterhub.orm import Base
from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import Unicode
from tornado.log import app_log


class TwoFAORM(Base):
    """Information for TwoFA code."""

    __tablename__ = "TwoFA"
    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    code = Column(Unicode(255), default="")
    generated = Column(Unicode(255), default="")
    expired = Column(Unicode(255), default="")

    def __repr__(self):
        return "<TwoFA for {}>".format(self.user_id)

    @classmethod
    def find(cls, db, user_id):
        """Find a group by user_id.
        Returns None if not found.
        """
        return db.query(cls).filter(cls.user_id == user_id).first()

    def validate_token(cls, db, user_id, code):
        """If token is valide return True, otherwise False"""
        obj = (
            db.query(cls).filter(cls.user_id == user_id).filter(cls.code == code).all()
        )
        app_log.debug("Query result: {}".format(obj))
        if len(obj) > 1 or len(obj) == 0:
            return False
        return obj[0]
