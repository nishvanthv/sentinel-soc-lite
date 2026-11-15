"""Transparent supplemental authentication detections."""
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from src.log_parser import AuthEvent
@dataclass(frozen=True)
class EngineAlert:
    alert_id:str; rule_id:str; title:str; severity:str; source_ip:str
    usernames:tuple[str,...]; attempts:int; first_seen:str; last_seen:str
    evidence:tuple[str,...]; mitre_technique:str; recommendation:str; risk_score:int
def _make(rule,title,severity,ip,events,technique,recommendation,risk):
    ordered=sorted(events,key=lambda e:e.timestamp); users=tuple(sorted({e.username for e in ordered}))
    key=f"{rule}|{ip}|{ordered[0].timestamp.isoformat()}|{','.join(users)}"
    return EngineAlert("ALT-"+sha256(key.encode()).hexdigest()[:12].upper(),rule,title,severity,ip,users,len(ordered),
        ordered[0].timestamp.isoformat(),ordered[-1].timestamp.isoformat(),
        tuple(f"{e.timestamp.isoformat()} {e.status} user={e.username}" for e in ordered[-20:]),technique,recommendation,risk)
def detect_password_spraying(events,threshold=5,window=timedelta(minutes=10)):
    grouped=defaultdict(list)
    for e in events:
        if e.status=="FAILED": grouped[e.ip].append(e)
    result=[]
    for ip,items in grouped.items():
        items.sort(key=lambda e:e.timestamp)
        for end,e in enumerate(items):
            start=end
            while start>0 and e.timestamp-items[start-1].timestamp<=window: start-=1
            group=items[start:end+1]
            if len({x.username for x in group})>=threshold:
                result.append(_make("AUTH-PASSWORD-SPRAY","Possible password spraying","HIGH",ip,group,"T1110.003",
                    "Review targeted accounts and source activity; consider rate limiting after analyst validation.",75)); break
    return result
def detect_distributed_brute_force(events,threshold=5,window=timedelta(minutes=10)):
    grouped=defaultdict(list)
    for e in events:
        if e.status=="FAILED": grouped[e.username].append(e)
    result=[]
    for user,items in grouped.items():
        items.sort(key=lambda e:e.timestamp)
        for end,e in enumerate(items):
            start=end
            while start>0 and e.timestamp-items[start-1].timestamp<=window: start-=1
            group=items[start:end+1]
            if len({x.ip for x in group})>=threshold:
                result.append(_make("AUTH-DISTRIBUTED-BRUTE","Possible distributed brute force","HIGH","multiple",group,"T1110",
                    "Review source diversity and account activity; validate before applying account controls.",80)); break
    return result
def run_detection_engine(events):
    return detect_password_spraying(events)+detect_distributed_brute_force(events)
