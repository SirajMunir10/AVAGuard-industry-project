"""SQLite database for local scan storage."""

from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, Session
from sqlalchemy.sql import func
import uuid
from pathlib import Path
from datetime import datetime

Base = declarative_base()

class LocalScan(Base):
    """One complete compliance scan."""
    __tablename__ = 'local_scans'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(100), nullable=False)
    timestamp = Column(DateTime, default=datetime.now)
    sync_status = Column(String(20), default='PENDING')  # PENDING or SYNCED
    overall_score = Column(String(10), default="0")
    
    results = relationship("CheckResult", back_populates="scan", cascade="all, delete-orphan")

class CheckResult(Base):
    """Result of one CIS control check."""
    __tablename__ = 'check_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey('local_scans.id'))
    control_code = Column(String(20))  # e.g., "1.1"
    status = Column(String(20))        # PASS or FAIL
    details = Column(Text)
    remediation = Column(Text)
    passed_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    
    scan = relationship("LocalScan", back_populates="results")
    resources = relationship("AffectedResource", back_populates="result", cascade="all, delete-orphan")

class AffectedResource(Base):
    """Specific resource that failed a check."""
    __tablename__ = 'affected_resources'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    check_result_id = Column(Integer, ForeignKey('check_results.id'))
    resource_name = Column(String(255))  # e.g., "admin@company.com"
    resource_type = Column(String(50))   # User, Device
    details = Column(Text)
    
    result = relationship("CheckResult", back_populates="resources")

class DatabaseManager:
    """Manage SQLite database operations."""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = Path.home() / "AppData" / "Local" / "AVAGuard" / "avaguard_local.db"
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.engine = create_engine(f'sqlite:///{self.db_path}')
        
    def init_db(self):
        """Create all tables."""
        Base.metadata.create_all(self.engine)
        print(f"✓ Database created: {self.db_path}")
        return True
    
    def save_scan_result(self, scan_id: str, tenant_id: str, results: list):
        """Save scan results to database."""
        from sqlalchemy.orm import sessionmaker
        Session = sessionmaker(bind=self.engine)
        session = Session()
        
        try:
            # Create scan
            scan = LocalScan(id=scan_id, tenant_id=tenant_id)
            session.add(scan)
            session.flush()
            
            # Add results
            for result_data in results:
                check = CheckResult(
                    scan_id=scan_id,
                    control_code=result_data.get('check_id'),
                    status=result_data.get('status'),
                    details=result_data.get('details'),
                    passed_count=result_data.get('compliant_count', 0),
                    failed_count=result_data.get('non_compliant_count', 0)
                )
                session.add(check)
            
            session.commit()
            print(f"✓ Scan saved: {scan_id}")
            return True
        except Exception as e:
            session.rollback()
            print(f"✗ Error saving scan: {e}")
            return False
        finally:
            session.close()
    
    def get_recent_scans(self, limit: int = 10):
        """Get recent scans from database."""
        from sqlalchemy.orm import sessionmaker
        Session = sessionmaker(bind=self.engine)
        session = Session()
        
        try:
            scans = session.query(LocalScan).order_by(
                LocalScan.timestamp.desc()
            ).limit(limit).all()
            return scans
        finally:
            session.close()