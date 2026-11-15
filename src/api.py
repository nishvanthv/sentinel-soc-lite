"""FastAPI endpoints for event ingestion and incident triage."""
from datetime import datetime
from ipaddress import ip_address
from fastapi import FastAPI,Depends,HTTPException,Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel,Field
from sqlalchemy.orm import Session
from sqlalchemy import select,func
from src.database import Base,engine,get_db
from src.models import EventRecord,AlertRecord,IncidentRecord
from src.log_parser import AuthEvent
from src.engine import run_detection_engine
app=FastAPI(title="Sentinel SOC Lite API",version="2.0.0",description="Defensive authentication telemetry and triage API")
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:5173","http://127.0.0.1:5173"],allow_credentials=False,allow_methods=["GET","POST","PATCH"],allow_headers=["Content-Type"])
Base.metadata.create_all(bind=engine)
class EventInput(BaseModel):
    timestamp:datetime
    username:str=Field(min_length=1,max_length=128)
    source_ip:str=Field(min_length=3,max_length=45)
    status:str
class IngestRequest(BaseModel): events:list[EventInput]=Field(min_length=1,max_length=5000)
class StatusInput(BaseModel): status:str
@app.get("/health")
def health(): return {"status":"ok","service":"sentinel-soc-lite"}
@app.get("/api/v1/summary")
def summary(db:Session=Depends(get_db)):
    count=lambda model:db.scalar(select(func.count()).select_from(model)) or 0
    return {"events":count(EventRecord),"alerts":count(AlertRecord),"incidents_open":db.scalar(select(func.count()).select_from(IncidentRecord).where(IncidentRecord.status!="RESOLVED")) or 0}
@app.post("/api/v1/events/ingest")
def ingest(payload:IngestRequest,db:Session=Depends(get_db)):
    parsed=[]
    for item in payload.events:
        status=item.status.upper()
        if status not in {"SUCCESS","FAILED"}: raise HTTPException(422,"status must be SUCCESS or FAILED")
        if item.timestamp.tzinfo is None: raise HTTPException(422,"timestamp must include timezone")
        try: ip=str(ip_address(item.source_ip))
        except ValueError: raise HTTPException(422,"invalid source_ip")
        parsed.append(AuthEvent(item.timestamp,item.username,ip,status))
        db.add(EventRecord(timestamp=item.timestamp,username=item.username,source_ip=ip,status=status))
    alerts=run_detection_engine(parsed)
    for a in alerts:
        if db.get(AlertRecord,a.alert_id) is None:
            db.add(AlertRecord(id=a.alert_id,rule_id=a.rule_id,title=a.title,severity=a.severity,source_ip=a.source_ip,usernames=list(a.usernames),attempts=a.attempts,first_seen=a.first_seen,last_seen=a.last_seen,evidence=list(a.evidence),mitre_technique=a.mitre_technique,recommendation=a.recommendation,risk_score=a.risk_score))
            db.add(IncidentRecord(id="INC-"+a.alert_id[4:],title=a.title,severity=a.severity,risk_score=a.risk_score,source_ip=a.source_ip,alert_ids=[a.alert_id],first_seen=a.first_seen,last_seen=a.last_seen))
    db.commit()
    return {"ingested":len(parsed),"alerts_created":len(alerts),"alert_ids":[a.alert_id for a in alerts]}
@app.get("/api/v1/alerts")
def alerts(limit:int=Query(100,ge=1,le=500),db:Session=Depends(get_db)):
    rows=db.scalars(select(AlertRecord).order_by(AlertRecord.created_at.desc()).limit(limit)).all()
    return [{"id":r.id,"rule_id":r.rule_id,"title":r.title,"severity":r.severity,"source_ip":r.source_ip,"usernames":r.usernames,"attempts":r.attempts,"first_seen":r.first_seen,"last_seen":r.last_seen,"evidence":r.evidence,"mitre_technique":r.mitre_technique,"recommendation":r.recommendation,"risk_score":r.risk_score} for r in rows]
@app.get("/api/v1/incidents")
def incidents(db:Session=Depends(get_db)):
    rows=db.scalars(select(IncidentRecord).order_by(IncidentRecord.first_seen.desc())).all()
    return [{"id":r.id,"title":r.title,"severity":r.severity,"risk_score":r.risk_score,"source_ip":r.source_ip,"alert_ids":r.alert_ids,"status":r.status,"first_seen":r.first_seen,"last_seen":r.last_seen} for r in rows]
@app.patch("/api/v1/incidents/{incident_id}")
def update_incident(incident_id:str,payload:StatusInput,db:Session=Depends(get_db)):
    if payload.status not in {"NEW","INVESTIGATING","ESCALATED","RESOLVED"}: raise HTTPException(422,"unsupported status")
    row=db.get(IncidentRecord,incident_id)
    if row is None: raise HTTPException(404,"incident not found")
    row.status=payload.status;db.commit()
    return {"id":row.id,"status":row.status}
