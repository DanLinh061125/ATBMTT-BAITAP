# Bài tập An toàn & Bảo mật thông tin

## Chạy
```
cd Bai1_AES && dotnet run
cd Bai2_RSA && dotnet run
```
Yêu cầu .NET 8 SDK trở lên. Giao diện console; nếu cần Form (WinForms), tạo project WinForms và gọi lại
các hàm EncryptFile/DecryptFile/CompareFiles... (logic không phụ thuộc giao diện).

## Bài 1 - AES: cách làm thử nghiệm
1. Menu 8: tạo file test (vd 1024 MB, 4096 MB...). 2. Menu 1 sinh khoá, menu 2 lưu. 3. Menu 9: tự chạy mã hoá -> giải mã -> so sánh byte, in thời gian và MB/s.
4. Lặp với 100 MB, 1 GB, 4 GB, 8 GB và ghi bảng số liệu (kích thước / t mã hoá / t giải mã / MB/s / kết quả so sánh).

Gợi ý kết luận (dựa vào số liệu của bạn):
- Thời gian tăng gần tuyến tính theo kích thước file (MB/s gần như không đổi) vì xử lý theo stream, bộ nhớ dùng cố định ~ vài MB.
- Giải mã CBC thường nhanh hơn/ngang mã hoá (CBC giải mã song song hoá được, mã hoá thì không); tốc độ phụ thuộc đĩa (I/O) nhiều khi hơn là CPU.
- File mã hoá lớn hơn bản gốc 16-32 byte (IV 16 byte + padding PKCS7).
- So sánh theo byte: nguồn và bản giải mã giống hệt => mã hoá/giải mã bảo toàn dữ liệu.

## Bài 2 - Ý nghĩa các byte trong PEM
PEM = `-----BEGIN <nhãn>-----` + base64 (64 ký tự/dòng) của dữ liệu nhị phân DER + `-----END <nhãn>-----`.
DER là các khối TLV: Tag (1 byte) - Length - Value. `30`=SEQUENCE, `02`=INTEGER, `03`=BIT STRING, `04`=OCTET STRING, `05`=NULL, `06`=OID.
Length: < 128 thì 1 byte; còn lại byte đầu = `80 + số byte độ dài` (vd `82 01 22` = dài 0x0122 = 290 byte).

Public key (`BEGIN PUBLIC KEY`, X.509 SubjectPublicKeyInfo), RSA 2048 = 294 byte:
```
30 82 01 22                      SEQUENCE (290 byte)
  30 0D                          SEQUENCE AlgorithmIdentifier
    06 09 2A 86 48 86 F7 0D 01 01 01   OID 1.2.840.113549.1.1.1 = rsaEncryption
    05 00                        NULL (tham số)
  03 82 01 0F 00                 BIT STRING (00 = số bit đệm)
    30 82 01 0A                  SEQUENCE RSAPublicKey
      02 82 01 01 00 <256 byte>  INTEGER n (00 đầu vì bit cao = 1)
      02 03 01 00 01             INTEGER e = 65537
```
Private key (`BEGIN PRIVATE KEY`, PKCS#8): SEQUENCE { INTEGER 0 (version), SEQUENCE {OID rsaEncryption, NULL}, OCTET STRING { SEQUENCE RSAPrivateKey { version, n, e, d, p, q, dp, dq, qInv } } }.
(Nhãn `BEGIN RSA PRIVATE KEY` là PKCS#1: chỉ có phần RSAPrivateKey, không có lớp bọc.)

## Vì sao tối đa 190 byte?
RSA-2048 => k = 256 byte. OAEP-SHA256 chiếm 2*32 + 2 = 66 byte => 256 - 66 = 190 byte. (Khoá AES-256 = 32 byte là dư sức.)
Thực tế RSA chỉ dùng để mã hoá khoá AES (mã hoá lai), dữ liệu lớn mã hoá bằng AES.

## Tốc độ: public key vs private key
e = 65537 (17 bit, chỉ 2 bit 1) => m^e mod n chỉ cần ~17 phép bình phương + 1 phép nhân.
d cỡ bằng n (2048 bit) => ~2048 phép bình phương + ~1024 phép nhân. Vì vậy mã hoá bằng public key nhanh hơn
giải mã bằng private key hàng chục - trăm lần (menu 6 sẽ đo; phần B không dùng CRT nên chênh lệch lớn,
phần A dùng CRT (p, q, dp, dq, qInv) nên giải mã chỉ chậm hơn mã hoá cỡ 10-50 lần). Khoá càng dài, giải mã càng chậm (~ bậc 3 theo số bit).

## SHA-256: hiệu ứng thác (avalanche)
Đổi 1 ký tự (thậm chí 1 bit) đầu vào => ~128/256 bit (~50%) của hash thay đổi, hash mới hoàn toàn không liên quan hash cũ.
Menu 7 in số bit khác cho từng lần nhập và thống kê trung bình 2000 lần đổi 1 bit.

## Chữ ký số: cùng dữ liệu, cùng private key, mỗi lần ký ra chữ ký khác nhau
Vấn đề: RSA PKCS#1 v1.5 là xác định (deterministic): sig = (padding || SHA256(data))^d mod n => cùng dữ liệu luôn ra cùng chữ ký.
Đề xuất:
1. **RSA-PSS (RSASSA-PSS, RFC 8017) - nên dùng.** Trước khi ký, trộn thêm **salt ngẫu nhiên**: M' = 0x00*8 || H(data) || salt; H2 = SHA256(M'); khối EM được che bằng MGF1(H2) rồi mới luỹ thừa bằng d. Mỗi lần ký salt khác => chữ ký khác nhau hoàn toàn nhưng người nhận vẫn verify được vì salt được khôi phục từ chính chữ ký. Trong .NET: `SignData(data, SHA256, RSASignaturePadding.Pss)`. PSS còn có chứng minh an toàn chặt hơn PKCS#1 v1.5.
2. **Nonce/timestamp:** ký SHA256(data || nonce) với nonce ngẫu nhiên 16-32 byte (hoặc thời gian), gửi kèm (data, nonce, chữ ký). Người nhận ghép data||nonce rồi verify. Ưu điểm: dễ hiểu, dùng được với bất kỳ thuật toán nào; nhược: nonce là một phần của giao thức, nên đưa vào gói tin.
3. (Tham khảo) ECDSA vốn ngẫu nhiên vì mỗi lần ký dùng số ngẫu nhiên k khác nhau (lộ/lặp k sẽ lộ private key).
Lưu ý: tính ngẫu nhiên không làm yếu việc kiểm chứng; chữ ký nào cũng verify đúng bằng cùng public key. Menu 8 chứng minh cả 3 cách (PKCS#1 giống nhau; PSS và nonce khác nhau mỗi lần).
