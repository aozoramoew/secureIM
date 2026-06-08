"""
Script tạo nhanh các user test trong database SecureIM.
Chạy: python create_test_users.py
"""
from app.database import SessionLocal
from app.models import User, DeviceKey
from app.crypto_utils import hash_password
import uuid

db = SessionLocal()

test_users = [
    {'username': 'testuser1', 'email': 'testuser1@test.com', 'password': 'password123'},
    {'username': 'testuser2', 'email': 'testuser2@test.com', 'password': 'password123'},
    {'username': 'alice',     'email': 'alice@test.com',     'password': 'password123'},
    {'username': 'bob',       'email': 'bob@test.com',       'password': 'password123'},
]

created = []
skipped = []

for ud in test_users:
    name = ud['username']
    existing = db.query(User).filter_by(username=name).first()
    if existing:
        skipped.append(name)
        continue

    u = User(
        username=name,
        email=ud['email'],
        password_hash=hash_password(ud['password']),
        is_email_verified=True,
    )
    db.add(u)
    db.flush()

    # Thêm device key placeholder để user có thể hiện trong danh sách
    dev_id = str(uuid.uuid4())
    dk = DeviceKey(
        user_id=u.id,
        device_id=dev_id,
        ecdsa_public_key='{"kty":"EC","crv":"P-384","x":"placeholder","y":"placeholder"}',
        ecdh_public_key='{"kty":"EC","crv":"P-256","x":"placeholder","y":"placeholder"}',
        device_name='Test Device',
        is_active=True,
    )
    db.add(dk)
    created.append(name)

db.commit()

# Confirm
all_users = db.query(User).all()
print(f"\n{'='*40}")
print(f"  Created : {created if created else 'none (all existed)'}")
print(f"  Skipped : {skipped}")
print(f"\n  All users in DB ({len(all_users)}):")
for u in all_users:
    print(f"    id={u.id}  username={u.username}  verified={u.is_email_verified}")
print(f"{'='*40}")
print("  Password for all test users: password123")
print(f"{'='*40}\n")

db.close()
