from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.database import SessionLocal  # noqa: E402
from app.models import Branch, Coach, Package  # noqa: E402


def main() -> None:
    db = SessionLocal()
    try:
        branches = [
            {"code": "TST", "name": "尖沙咀分店", "address": "柯士甸道102號22樓"},
            {"code": "SHEUNGWAN", "name": "上環分店", "address": "宏基商業大廈一樓全層"},
        ]
        for item in branches:
            row = db.query(Branch).filter(Branch.code == item["code"]).first()
            if row is None:
                db.add(Branch(**item))
            else:
                row.name = item["name"]
                row.address = item["address"]
                row.active = True

        first_branch = db.query(Branch).order_by(Branch.id).first()
        if first_branch and db.query(Coach).count() == 0:
            db.add(Coach(full_name="Zomate Coach", phone="00000000", branch_id=first_branch.id, specialty="General", active=True))

        packages = [
            {"name": "10 堂套票", "sessions": 10, "price": 0},
            {"name": "30 堂套票", "sessions": 30, "price": 0},
        ]
        for item in packages:
            row = db.query(Package).filter(Package.name == item["name"]).first()
            if row is None:
                db.add(Package(**item))
            else:
                row.sessions = item["sessions"]
                row.price = item["price"]
                row.active = True

        db.commit()
        print("Seed complete.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
