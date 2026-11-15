"""Persistent event, alert and incident records."""
from datetime import datetime,timezone
from sqlalchemy import DateTime,Integer,String,Text,JSON
from sqlalchemy.orm import Mapped,mapped_column
from src.database import Base
class EventRecord(Base):
    __tablename__="auth_events"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    timestamp:Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    username:Mapped[str]=mapped_column(String(128),index=True)
    source_ip:Mapped[str]=mapped_column(String(45),index=True)
    status:Mapped[str]=mapped_column(String(8),index=True)
class AlertRecord(Base):
    __tablename__="alerts"
    id:Mapped[str]=mapped_column(String(40),primary_key=True)
    rule_id:Mapped[str]=mapped_column(String(80),index=True)
    title:Mapped[str]=mapped_column(String(200))
    severity:Mapped[str]=mapped_column(String(16),index=True)
    source_ip:Mapped[str]=mapped_column(String(45),index=True)
    usernames:Mapped[list]=mapped_column(JSON)
    attempts:Mapped[int]=mapped_column(Integer)
    first_seen:Mapped[str]=mapped_column(String(40))
    last_seen:Mapped[str]=mapped_column(String(40))
    evidence:Mapped[list]=mapped_column(JSON)
    mitre_technique:Mapped[str]=mapped_column(String(32))
    recommendation:Mapped[str]=mapped_column(Text)
    risk_score:Mapped[int]=mapped_column(Integer)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
class IncidentRecord(Base):
    __tablename__="incidents"
    id:Mapped[str]=mapped_column(String(40),primary_key=True)
    title:Mapped[str]=mapped_column(String(200))
    severity:Mapped[str]=mapped_column(String(16))
    risk_score:Mapped[int]=mapped_column(Integer)
    source_ip:Mapped[str]=mapped_column(String(45),index=True)
    alert_ids:Mapped[list]=mapped_column(JSON)
    status:Mapped[str]=mapped_column(String(24),default="NEW",index=True)
    first_seen:Mapped[str]=mapped_column(String(40))
    last_seen:Mapped[str]=mapped_column(String(40))
