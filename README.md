# Free Fire VN IL2CPP Dumper

Công cụ trích xuất `libil2cpp.so`, `libanort.so` và `global-metadata.dat` từ gói cài đặt Android của Free Fire VN (`.xapk`, `.apks`, `.apk`, `.zip`), giải mã và khôi phục thứ tự các block `.rodata` (AES-128-CBC + XOR + hoán vị 16 KB), đọc cấu trúc metadata v31 mở rộng (`Il2CppMethodDefinition` 40 byte), rồi xuất `DummyDll`, `dump.cs`, `il2cpp.h`, `script.json` và `stringliteral.json`.

---

## 1. Thành phần thư mục

- `FFVN Dumper.exe`: Chương trình chính (Windows x64 self-contained single-file, không cần cài thêm .NET Runtime).
- `config.json`: Cấu hình `Il2CppDumper` đặt cạnh file `.exe`.
- `*.py`: Bộ script hỗ trợ nạp struct và symbol cho IDA Pro, Ghidra, Binary Ninja, Hopper (`ida_with_struct.py` và `ida_with_struct_py3.py` được tự động chép vào thư mục kết quả).
- `Output/`: Thư mục mặc định lưu kết quả mỗi lần chạy.
- `Source/`: Mã nguồn gồm `FFVN.Dumper` (WPF GUI + CLI) và `Il2CppDumper.Core` (`FreeFireUnpacker`, `Metadata` v31 mở rộng).

---

## 2. Hỗ trợ định dạng đầu vào

Hỗ trợ `.xapk`, `.apks`, `.apk`, `.zip` chứa:

1. `lib/<abi>/libil2cpp.so` (`arm64-v8a` hoặc `armeabi-v7a`, hỗ trợ cả split APK như `config.armeabi_v7a.apk` / `config.arm64_v8a.apk`)
2. `lib/<abi>/libanort.so` (tùy chọn — dùng để đọc bảng hoán vị 8-block `.rodata` trực tiếp; nếu thiếu sẽ tự suy diễn từ ranh giới `.rodata`)
3. `assets/bin/Data/Managed/Metadata/global-metadata.dat` (bao gồm các gói tải thêm như `asset_pack_install_time.apk`)

---

## 3. Cách sử dụng

### Cách 1: Giao diện đồ họa (GUI)

1. Chạy `FFVN Dumper.exe` (không truyền tham số).
2. **Gói game**: Chương trình tự gợi ý gói `.xapk`/`.apk` của Free Fire nếu đặt cùng thư mục hoặc ở thư mục cha. Có thể bấm **Chọn APK / XAPK** hoặc kéo thả trực tiếp file `.xapk` / `.apks` / `.apk` / `.zip` vào cửa sổ.
3. **Thư mục lưu**: Mặc định là `Output` cạnh file `.exe` (bấm **Chọn thư mục** để đổi).
4. Bấm **Bắt đầu dump** và chờ thông báo `Hoàn tất (...) — ... DummyDll, ... types.` cùng các badge thống kê `ABI`, `Seed / Perm` và tổng số methods; sau đó bấm **Mở kết quả** để mở thư mục vừa dump.

### Cách 2: Dòng lệnh (CLI)

```powershell
& ".\FFVN Dumper.exe" --dump "<đường_dẫn_gói.xapk|apks|apk|zip>" ["<thư_mục_lưu_kết_quả>"]
```

- Nếu bỏ qua `<thư_mục_lưu_kết_quả>`, kết quả sẽ lưu vào `Output` cạnh `FFVN Dumper.exe`.
- Mã thoát (`ExitCode`): `0` khi thành công (in `DUMP_SUCCESS <đường_dẫn_kết_quả>`), `1` khi có lỗi.

---

## 4. Thư mục kết quả

Mỗi lần chạy tạo một thư mục con theo mẫu `<tên_gói>_<yyyyMMdd_HHmmss>_<6_ký_tự_ngẫu_nhiên>`:

| Thành phần | Mô tả |
|---|---|
| `Input/libil2cpp.original.so` | Binary gốc trích từ gói (nếu bị mã hóa stub) |
| `Input/libil2cpp.so` | Binary sau giải mã `.rodata` & khôi phục thứ tự block (dùng trực tiếp cho IDA/Ghidra) |
| `Input/libanort.so` | Thư viện đi kèm dùng trích bảng hoán vị (nếu có trong gói) |
| `Input/global-metadata.dat` | Metadata trích xuất từ gói |
| `DummyDll/` | Bộ assembly giả `.dll` để mở trong dnSpy / ILSpy |
| `dump.cs` | Danh sách class, field, property, method, attribute và offset/RVA |
| `il2cpp.h` | Header C/C++ phục vụ IDA / Ghidra / Binary Ninja |
| `script.json` | Ánh xạ địa chỉ hàm, metadata, string literal |
| `stringliteral.json` | Danh sách string literal đã trích xuất |
| `ida_with_struct.py`, `ida_with_struct_py3.py` | Script nạp tên hàm và struct vào IDA |
| `result.json` | Thống kê metadata, thông số giải mã `.rodata` và SHA-256 các file xuất |
| `dump.log` | Nhật ký chi tiết toàn bộ quá trình chạy |

---

## 5. Bản quyền & Ghi công

- Tác giả: **© 2026 quangbaong (BANNEI)** — https://github.com/quangbaong
- Kho lưu trữ: https://github.com/quangbaong/FFVN_il2cppdumper
- Lõi phân tích dựa trên [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) (Perfare / AndnixSH) theo giấy phép [LICENSE-Il2CppDumper.txt](LICENSE-Il2CppDumper.txt).
