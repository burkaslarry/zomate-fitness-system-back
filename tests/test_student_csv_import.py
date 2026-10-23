"""[F001][S003] Numbers member CSV regression tests, with synthetic data only."""
import csv
import io
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, UploadFile
from app import main
from app.excel_csv_compat import fix_fung_student_csv_headers
from app.models import LessonLedgerEntry, Student

HEADERS = 'MemberCode,PT,Name,Gender,phone number,Date of Birth,ID Number,Emergency Contact,Emergency Contact Number\r\n'
SAMPLE = ('Table 1\r\n' + HEADERS +
          '9000 0001,Coach QA,"Tester, One",F,9000 0001,1999/12/28,,Emergency QA (Dad),90000002\r\n')


def upload(text):
    """[F007][S005] In-memory upload, never a real member export."""
    return UploadFile(filename='memberinfo.csv', file=io.BytesIO(text.encode('utf-8-sig')))


def test_numbers_title_imports_and_reimports_without_duplicates(db_session):
    """[F001][S003] Original Numbers shape reaches persistence and preserves quoted commas."""
    user = SimpleNamespace(role='ADMIN')
    first = main.import_students_csv(upload(SAMPLE), db_session, user)
    assert (first['imported'], first['updated'], first['skipped']) == (1, 0, 0)
    student = db_session.query(Student).one()
    assert student.full_name == 'Tester, One'
    assert student.phone == '+85290000001'
    assert student.gender == 'female'
    assert student.date_of_birth.isoformat() == '1999-12-28'
    assert student.emergency_contact_name == 'Emergency QA'
    assert student.emergency_contact_relationship == 'Dad'
    assert student.emergency_contact_phone == '90000002'
    second = main.import_students_csv(upload(SAMPLE), db_session, user)
    assert (second['imported'], second['updated'], second['skipped']) == (0, 1, 0)
    assert db_session.query(Student).count() == 1


def test_roster_without_balance_or_optional_columns_preserves_existing_data(db_session):
    """[F001][S003] Re-importing contact data must not reset purchased lessons or consent."""
    student = Student(full_name='Tester, One', phone='90000001', email='qa@example.invalid',
                      health_notes='Existing note', disclaimer_accepted=False, face_id_external='qa-face')
    db_session.add(student)
    db_session.flush()
    db_session.add(LessonLedgerEntry(student_id=student.id, delta_lessons=7, reason='qa', created_by_role='admin'))
    db_session.commit()
    result = main.import_students_csv(upload(SAMPLE), db_session, SimpleNamespace(role='ADMIN'))
    assert result['updated'] == 1
    assert main._lesson_balance_sum(db_session, student.id) == 7
    assert db_session.query(LessonLedgerEntry).count() == 1
    assert student.email == 'qa@example.invalid'
    assert student.health_notes == 'Existing note'
    assert student.disclaimer_accepted is False
    assert student.face_id_external == 'qa-face'


def test_zero_placeholder_preserves_existing_balance(db_session):
    """[F001][S003] An explicitly supplied balance retains the existing import contract."""
    student = Student(full_name='QA Balance', phone='90000003')
    db_session.add(student)
    db_session.flush()
    db_session.add(LessonLedgerEntry(student_id=student.id, delta_lessons=7, reason='qa', created_by_role='admin'))
    db_session.commit()
    result = main.import_students_csv(upload('full_name,phone,lesson_balance\nQA Balance,90000003,0\n'), db_session, SimpleNamespace(role='ADMIN'))
    assert result['updated'] == 1
    assert main._lesson_balance_sum(db_session, student.id) == 7


@pytest.mark.parametrize('prefix', ['', '\n', 'Table 1\n', '\nTable 1,,,\n\n', '表格 1\n', 'table 12\r\n'])
def test_recognized_preambles_preserve_real_header(prefix):
    """[F001][S003] Standard CSV and Numbers exports share the same alias mapping."""
    normalized = fix_fung_student_csv_headers(prefix + HEADERS + '90000001,QA,Tester,F,90000001,,,,\n')
    rows = list(csv.DictReader(io.StringIO(normalized)))
    assert rows[0]['Name'] == 'Tester'
    assert len(rows) == 1


def test_payment_sheet_is_not_silently_skipped(db_session):
    """[F001][S003] Reject payment data rather than scan down to unrelated name-like cells."""
    text = 'Table 1\n電話號碼,收費,付款方法\n90000001,100,FPS\n' + HEADERS
    with pytest.raises(HTTPException) as exc:
        main.import_students_csv(upload(text), db_session, SimpleNamespace(role='ADMIN'))
    assert exc.value.status_code == 400
    assert '收錢' in exc.value.detail
    assert db_session.query(Student).count() == 0


def test_phone_collision_with_other_name_remains_a_skip(db_session):
    """[F001][S003] A repeated phone is not permission to overwrite a different person."""
    db_session.add(Student(full_name='Different QA', phone='+85290000001'))
    db_session.commit()
    result = main.import_students_csv(upload(SAMPLE), db_session, SimpleNamespace(role='ADMIN'))
    assert result['skipped'] == 1
    assert result['skip_reasons'][0]['code'] == 'phone_exists_name_mismatch'
    assert db_session.query(Student).one().full_name == 'Different QA'
