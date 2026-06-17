# WAF Attack Simulation — SecureIM

Bộ script này gửi các request mô phỏng tấn công đến **chính app SecureIM của bạn** để demo
khả năng phát hiện của ML-WAF. Chỉ dùng trên môi trường dev/staging mà bạn sở hữu.

## Yêu cầu

- Python 3.11+  (dùng venv của project)
- App SecureIM đang chạy
- ML-WAF sidecar đang chạy (hoặc dùng mock bên dưới)

## Chạy nhanh

```powershell
# 1. Khởi động app (terminal 1)
cd c:\Projects\secureIM
.\venv311\Scripts\python.exe run.py

# 2. Khởi động ML-WAF sidecar (terminal 2) — hoặc mock bên dưới
# (tùy cấu hình deployment)

# 3. Chạy toàn bộ test (terminal 3)
cd c:\Projects\secureIM
.\venv311\Scripts\python.exe tests\waf_attack_sim\run_all.py http://localhost:8000

# Hoặc chạy từng loại riêng lẻ:
.\venv311\Scripts\python.exe tests\waf_attack_sim\01_sqli.py        http://localhost:8000
.\venv311\Scripts\python.exe tests\waf_attack_sim\02_xss.py         http://localhost:8000
.\venv311\Scripts\python.exe tests\waf_attack_sim\03_path_traversal.py http://localhost:8000
.\venv311\Scripts\python.exe tests\waf_attack_sim\04_cmdi.py        http://localhost:8000
.\venv311\Scripts\python.exe tests\waf_attack_sim\05_ssrf.py        http://localhost:8000
.\venv311\Scripts\python.exe tests\waf_attack_sim\06_brute_force.py http://localhost:8000
.\venv311\Scripts\python.exe tests\waf_attack_sim\07_benign.py      http://localhost:8000
```

## Mock WAF sidecar (nếu chưa có sidecar thật)

Nếu bạn muốn demo WAF **blocking**, cần có sidecar thật.
Nếu chỉ muốn test **shape của request** gửi đến WAF, dùng mock:

```powershell
.\venv311\Scripts\python.exe tests\waf_attack_sim\mock_waf_sidecar.py
```

Mock này in ra mọi snapshot nhận được và luôn trả `ALLOW` (không block).
Thay `"decision": "ALLOW"` thành `"BLOCK"` trong mock để test 403 response.

## Output

Mỗi script in bảng kết quả:
- `BLOCKED (403)` — WAF phát hiện và chặn  ✅ mong đợi với payloads độc hại
- `ALLOWED (2xx/4xx)` — request đi qua WAF  ✅ mong đợi với requests lành mạnh
- `ALLOWED (2xx/4xx)` với payload độc hại   ⚠️  false negative — WAF miss
- `BLOCKED (403)` với request lành mạnh     ⚠️  false positive — WAF over-block
