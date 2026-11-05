# SỔ TAY VẬN HÀNH HỆ THỐNG & XỬ LÝ SỰ CỐ (`RUNBOOK.md`)

**Dự án:** **WordPress Manager** (`da_wp_toolkits`)  
**Phiên bản chính thức:** `v1.0.2`  
**Đối tượng sử dụng:** Quản trị viên máy chủ Linux / Nhà cung cấp dịch vụ Hosting sử dụng DirectAdmin (`1.670+`, Evolution Skin)

---

## 1. Sơ đồ Đường dẫn Chuẩn trên Máy chủ DirectAdmin

| Thành phần | Đường dẫn mặc định | Quyền sở hữu & Chế độ |
| :--- | :--- | :--- |
| Nhị phân CLI & Daemon | `/usr/local/sbin/da-wptoolkit` | `root:root` (`0755`) |
| Dịch vụ `systemd` | `/etc/systemd/system/da-wptoolkitd.service` | `root:root` (`0644`) |
| Admin Unix Socket | `/var/run/da-wptoolkit.sock` | `root:diradmin` (`0660`) |
| End-User Unix Socket | `/var/run/da-wptoolkit-user.sock` | `root:root` (`0666` + Guard 3 lớp) |
| Kho dữ liệu trạng thái & Registry | `/var/lib/da-wptoolkit/` | `root:root` (`0700`) |
| Khoá bí mật `CSRF HMAC` | `/var/lib/da-wptoolkit/secret/csrf.key` | `root:root` (`0600`) |
| Hầm cách ly mã độc (`Quarantine Vault`) | `/var/lib/da-wptoolkit/quarantine/<user>/` | `root:root` (`0700`) |
| Bản sao lưu tự động của Updater | `/var/lib/da-wptoolkit/backups/backup_*.tar.gz` | `root:root` (`0600`) |
| Kho đệm nhân WordPress (`Core Cache`) | `/var/cache/da-wptoolkit/wp-core/` | `root:root` (`0755`) |
| Cấu hình GitHub Updater & Token | `/etc/da-wptoolkit/updater.conf` | `root:root` (`0600`) |
| Cấu hình nhân `inotify` | `/etc/sysctl.d/90-da-wptoolkit.conf` | `root:root` (`0644`) |
| Giao diện Evolution Skin Plugin | `/usr/local/directadmin/plugins/da_wp_toolkits/` | `diradmin:diradmin` (`api.raw` `0755`) |
| Chính sách gói Hosting (`Policies`) | `/usr/local/directadmin/plugins/da_wp_toolkits/data/` | `diradmin:diradmin` (`0750`) |
| 9 DirectAdmin Lifecycle Hooks | `/usr/local/directadmin/scripts/custom/<hook>/da_wp_toolkits.sh` | `root:root` (`0700`) |
| Cấu hình bảo mật Nginx từng site | `/etc/nginx/da-wptoolkit/<instance_id>.conf` | `root:root` (`0644`) |

---

## 2. Triển khai Mới & Đóng gói Bản phát hành

### 2.1. Cài đặt 1-Click trên máy chủ DirectAdmin (`root`)
Trình cài đặt `scripts/install.sh` tự động kiểm tra kiến trúc CPU (`amd64`/`arm64`), xác thực `SHA-512` khi tải `wp-cli` (nếu máy chủ chưa có), nâng giới hạn `fs.inotify.max_user_watches = 524288`, cài đặt binary, Evolution Skin plugin, toàn bộ **9 DirectAdmin Hooks**, kích hoạt `da-wptoolkitd.service`, đồng bộ dữ liệu CVE và quét phát hiện toàn bộ website WordPress hiện có:

```bash
# Cài đặt trực tiếp từ bản phát hành đã biên dịch hoặc biên dịch tại chỗ nếu máy chủ có Go 1.22+
sudo bash scripts/install.sh
```

Có thể truyền biến môi trường để ghim phiên bản hoặc kho phát hành riêng:
```bash
sudo DA_WPTK_REPO="shostwp-byte/da-wordpresstoolkit" \
     DA_WPTK_VERSION="v1.0.2" \
     bash scripts/install.sh
```

### 2.2. Đóng gói Gói phát hành & DirectAdmin Plugin Manager
Để tạo trọn bộ hiện vật phát hành (`da-wptoolkit-linux-amd64.tar.gz`, `da-wptoolkit-linux-arm64.tar.gz`, gói cài đặt giao diện DirectAdmin `da_wp_toolkits.tar.gz` và bảng mã băm `checksums.txt`):

```bash
make package
```

Nếu đã có khoá bí mật `Ed25519`, ký số ngay trong bước đóng gói:
```bash
DA_WPTK_RELEASE_PRIVATE_KEY="<128_ky_tu_hex_private_key>" make package
```

---

## 3. Quản lý Chữ ký số `Ed25519` & Cập nhật Tự động (`TC-10`)

### 3.1. Tạo cặp khoá ký số phát hành (`Ed25519`)
Khi triển khai cho hệ thống nội bộ của nhà cung cấp Hosting (Self-Hosted Fork), tạo cặp khoá mới bằng chính công cụ tích hợp sẵn:

```bash
da-wptoolkit keygen
```
* Lưu `PRIVATE_KEY_HEX` (`64 bytes` / `128 hex chars`) vào GitHub Repository Secret mang tên `RELEASE_ED25519_PRIVATE_KEY` (phục vụ `.github/workflows/release.yml`).
* Gắn `PUBLIC_KEY_HEX` (`32 bytes` / `64 hex chars`) vào `internal/version/version.go` (`DefaultReleasePublicKeyHex`).

### 3.2. Ký số & Kiểm tra Gói phát hành thủ công
```bash
# Ký toàn bộ hiện vật trong dist/release -> sinh checksums.txt & checksums.txt.sig
DA_WPTK_RELEASE_PRIVATE_KEY="<128_ky_tu_hex_private_key>" \
  da-wptoolkit sign-release --dir dist/release

# Xác thực chữ ký số trước khi công bố lên GitHub Releases
da-wptoolkit verify-release --dir dist/release
```

### 3.3. Cập nhật Nguyên tử & Khôi phục Tức thời (Rollback `< 10s`)
Quá trình cập nhật tuân thủ nghiêm ngặt quy trình an toàn 6 bước:
1. Tải `checksums.txt` và `checksums.txt.sig` từ GitHub Releases.
2. Xác thực chữ ký số `Ed25519` bằng khoá công khai trước khi chấp nhận bất kỳ dữ liệu nào.
3. Tải gói `da-wptoolkit-linux-<arch>.tar.gz` và đối chiếu mã băm `SHA-256` khớp tuyệt đối với `checksums.txt`.
4. Đóng gói bản sao lưu trạng thái trước nâng cấp tại `/var/lib/da-wptoolkit/backups/backup_<version>_<timestamp>.tar.gz` (xoay vòng tự động theo `backup_retention`).
5. Hoán đổi nguyên tử binary + giao diện Evolution Skin + 9 Hooks (**bảo toàn nguyên vẹn** thư mục chính sách `plugin/data/` và kho Registry `/var/lib/da-wptoolkit/`), sau đó khởi động lại `da-wptoolkitd`.
6. Thực hiện `HealthCheck` qua Admin Socket trong tối đa `9 giây`. Nếu tiến trình mới gặp sự cố khởi động hoặc không phản hồi, trình cập nhật **tự động Rollback tức thì về bản sao lưu trước đó dưới 10 giây** (`TC-10`).

Các lệnh CLI phục vụ quản trị viên:
```bash
# Kiểm tra bản cập nhật mới trên kênh stable (hoặc --channel beta)
da-wptoolkit check-update

# Thực thi cập nhật nguyên tử lên phiên bản mới nhất (hoặc chỉ định --tag v1.0.1)
da-wptoolkit update

# Xem danh sách các bản sao lưu trước nâng cấp hiện có
da-wptoolkit rollback --list

# Khôi phục tức thời về bản sao lưu gần nhất (hoặc truyền --backup backup_....tar.gz)
da-wptoolkit rollback
```

---

## 4. Vận hành 9 DirectAdmin Lifecycle Subdirectory Hooks

Hệ thống đăng ký không xâm lấn tại `/usr/local/directadmin/scripts/custom/<hook>/da_wp_toolkits.sh` (tương thích hoàn toàn với CloudLinux, Imunify360, LiteSpeed và JetBackup đang dùng chung cơ chế Subdirectory Hooks của DirectAdmin):

1. `domain_create_post` & `subdomain_create_post`: Tự động nạp lại cấu trúc tên miền của khách hàng và quét phát hiện nếu mã nguồn WordPress vừa được giải nén sẵn.
2. `domain_destroy_post` & `subdomain_destroy_post`: Tự động thu hồi `inotify` watches, dọn cấu hình Nginx snippet và gỡ bản ghi instance mồ côi thuộc tên miền/tên miền phụ vừa xóa.
3. `user_modify_post`: Tự động nạp lại gói Hosting (`package`) từ `user.conf` để áp dụng ngay hạn mức `PackagePolicy` mới khi nâng/hạ gói.
4. `user_backup_pre` & `user_backup_post` (`TC-06`): Tự động mở khóa tạm thời các site đang bật **Fortress Core Lock (`root:<user>`)** về quyền sở hữu `<user>:<user>` trước khi DirectAdmin nén bản sao lưu `.tar.zst`, lưu danh sách khóa tại `/var/lib/da-wptoolkit/backup_locks.json` và khóa cứng trở lại ngay khi sao lưu hoàn tất.
5. `user_restore_post`: Tự động nạp lại `/etc/passwd` + `user.conf` và quét nhận diện ngay toàn bộ website WordPress của tài khoản vừa khôi phục từ máy chủ khác chuyển về.
6. `user_destroy_post`: Thu hồi toàn bộ `inotify` watches, dọn sạch Quarantine Vault, xóa cấu hình bảo mật Web Server và xóa sạch bản ghi Registry của tài khoản vừa bị hủy.

> **Lưu ý thiết kế an toàn:** Mọi tệp script Hook đều chạy không chặn luồng chính và luôn kết thúc bằng `exit 0` để đảm bảo ngay cả khi dịch vụ `da-wptoolkitd` đang bảo trì, các tác vụ tạo/xóa/sao lưu tài khoản gốc của DirectAdmin không bao giờ bị gián đoạn.

---

## 5. Xử lý Sự cố Thường gặp (Troubleshooting)

### 5.1. Kiểm tra nhanh trạng thái toàn hệ thống
```bash
# Chạy kịch bản chẩn đoán tiền kiểm tự động
sudo bash /usr/local/share/da-wptoolkit/scripts/qa_verify.sh preflight

# Kiểm tra trạng thái dịch vụ và nhật ký thời gian thực
systemctl status da-wptoolkitd
journalctl -u da-wptoolkitd -n 100 --no-pager
```

### 5.2. Khách hàng báo không sửa được tệp nhân WordPress qua FTP/File Manager
* **Nguyên nhân:** Website đang kích hoạt chế độ bảo vệ mức nhân hệ điều hành **Fortress Core Lock** (`root:<user> 0644/0755`) hoặc tính năng **Anti-Thrashing Guard** đã tự động nâng cấp lên Fortress Lock sau khi phát hiện tệp Core bị ghi đè lặp lại quá 5 lần/phút.
* **Cách xử lý chuẩn:** Người dùng cuối có thể chuyển chế độ bảo vệ về `Auto-Heal` hoặc `Monitor` ngay tại tab **Security** trên giao diện WordPress Manager, hoặc quản trị viên mở khóa qua CLI:
  ```bash
  # Kiểm tra danh sách instance và trạng thái bảo vệ
  da-wptoolkit list --user <username>
  ```
* **Cứu hộ khẩn cấp khi dừng dịch vụ:** Nếu cần mở khóa toàn bộ tệp nhân về quyền `<user>:<user>` mà dịch vụ đang dừng, trình gỡ cài đặt `scripts/uninstall.sh` đã tích hợp sẵn bộ đọc trực tiếp `/var/lib/da-wptoolkit/instances.json` để hoàn trả quyền sở hữu an toàn.

### 5.3. Lỗi chạm ngưỡng theo dõi tệp `inotify` (`ENOSPC` trên máy chủ mật độ cực cao)
* Kiểm tra số lượng watches hiện tại qua `da-wptoolkit ping` hoặc trên tab **Tổng quan Hệ thống** của Admin Panel.
* Nếu máy chủ lưu trữ trên `2.000+` website WordPress cùng bật Core Shield, tăng giới hạn tại `/etc/sysctl.d/90-da-wptoolkit.conf`:
  ```bash
  echo "fs.inotify.max_user_watches = 1048576" > /etc/sysctl.d/90-da-wptoolkit.conf
  sysctl --system
  systemctl restart da-wptoolkitd
  ```

### 5.4. Máy chủ DirectAdmin dừng đột ngột giữa lúc đang chạy Backup (`user_backup_pre`)
* Không cần can thiệp thủ công: Danh sách các instance tạm mở khóa đã được lưu bền vững trên đĩa tại `/var/lib/da-wptoolkit/backup_locks.json`. Ngay lần chạy `user_backup_post` kế tiếp hoặc khi gọi `da-wptoolkit hook user_backup_post --user <username>`, Daemon sẽ tự động khôi phục lại trạng thái `Fortress Core Lock`.

### 5.5. Tích hợp Bảo mật trên Nginx Standalone / Nginx-Apache Reverse Proxy
* Đối với Apache, LiteSpeed Enterprise và OpenLiteSpeed, 12 quy tắc bảo mật và HTTP Basic Auth được ghi trực tiếp vào khối đánh dấu `# BEGIN DA-WP-TOOLKIT HARDENING` trong `.htaccess` (với OpenLiteSpeed, Daemon tự động gom nhóm và kích hoạt `graceful reload` sau `2 giây` nghỉ).
* Đối với máy chủ thuần **Nginx Standalone**, hãy đảm bảo cấu hình mẫu VirtualHost tùy biến của DirectAdmin nạp thư mục snippet của plugin (hoặc thêm vào khối `server {}` của tên miền):
  ```nginx
  include /etc/nginx/da-wptoolkit/*.conf;
  ```
  Mọi thay đổi cấu hình Nginx từ Daemon đều bắt buộc vượt qua bước kiểm tra `nginx -t`; nếu phát hiện lỗi cú pháp, Daemon tự động hoàn tác tệp cấu hình cũ ngay lập tức.

---

## 6. Quy trình Gỡ Cài đặt An toàn (`scripts/uninstall.sh`)

Không bao giờ xóa thủ công thư mục plugin hoặc dừng đột ngột dịch vụ khi còn website đang bật **Fortress Core Lock**. Luôn sử dụng kịch bản gỡ cài đặt chuẩn:

```bash
# Gỡ cài đặt dịch vụ, giao diện và 9 Hooks nhưng GIỮ LẠI dữ liệu Registry & Quarantine Vault
sudo bash /usr/local/share/da-wptoolkit/scripts/uninstall.sh

# Hoặc gỡ bỏ hoàn toàn kèm xóa sạch toàn bộ dữ liệu trạng thái, cache và cấu hình
sudo bash /usr/local/share/da-wptoolkit/scripts/uninstall.sh --purge-data
```
Kịch bản `uninstall.sh` cam kết tự động mở khóa quyền sở hữu `<user>:<user>` cho mọi website đang bật `Fortress Core Lock` trước khi dừng `da-wptoolkitd`, đảm bảo 100% website của khách hàng tiếp tục vận hành và cập nhật bình thường sau khi gỡ plugin.
