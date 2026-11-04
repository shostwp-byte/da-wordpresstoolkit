# ĐẶC TẢ GIAO THỨC IPC & XÁC THỰC 3 LỚP (`IPC_PROTOCOL.md`)

**Dự án:** `DA-WordPressToolkits`  
**Phiên bản giao thức:** `1.0`  

---

## 1. Kiến trúc Dual Unix Domain Socket

Dịch vụ nền `da-wptoolkitd` lắng nghe đồng thời trên 2 Unix Domain Socket độc lập, mỗi kết nối xử lý 1 cặp `Request -> Response` định dạng **Newline-Delimited JSON (`\n`)**, giới hạn kích thước khung tin tối đa **64 KB** và thời gian chờ tối đa **15 giây**:

| Tên Socket | Đường dẫn mặc định | Đối tượng gọi hợp lệ | Giới hạn đồng thời |
| :--- | :--- | :--- | :--- |
| **Admin Socket** | `/var/run/da-wptoolkit.sock` | CLI `root`, DirectAdmin Hooks (`root`), CGI `admin/api.raw` (`admin.list` / `diradmin`) | `32` kết nối |
| **User Socket** | `/var/run/da-wptoolkit-user.sock` | CGI `user/api.raw` chạy dưới `UID` của tài khoản Hosting DirectAdmin (`1000..65533`) | `64` kết nối + Rate Limit `30 req / 5s / UID` |

---

## 2. Cơ chế Xác thực Zero-Trust 3 Lớp (Chống Web-Shell cùng UID — `TC-01`)

Ngay khi nhận kết nối (`Accept`), **trước khi đọc hoặc giải mã bất kỳ byte JSON nào**, `da-wptoolkitd` thực thi tuần tự:

1. **Lớp 1 — Kernel `SO_PEERCRED` (`PID`, `UID`, `GID`):**
   * Lấy trực tiếp định danh nhân Linux của tiến trình gọi qua `syscall.GetsockoptUcred`.
   * Với `UID == 0` (`root`) trên Admin Socket: Cho phép thực thi trực tiếp phục vụ CLI và Event Hooks hệ thống.
   * Với các `UID` khác: Đối chiếu với `dausers.Registry` (chặn cứng `nobody=65534` và các tài khoản không thuộc DirectAdmin).
2. **Lớp 2 — Kiểm chứng Cây Tiến Trình Cha (`DirectAdmin Lineage Guard`):**
   * Đọc `/proc/<pid>/cgroup`: Từ chối ngay lập tức (`403 Unauthorized Peer Lineage`) nếu tiến trình nằm trong `da-php.scope`, `php-fpm*`, `lshttpd`, `apache2`, `httpd`, `nginx` hoặc `sshd`.
   * Duyệt ngược chuỗi `PPid` qua `/proc/<pid>/stat` (tối đa 16 bậc) kiểm tra `/proc/<ancestor>/exe`: Bắt buộc phải có tổ tiên là `/usr/local/directadmin/directadmin` và không chứa bất kỳ tiến trình worker web/cron/SSH nào ở giữa.
3. **Lớp 3 — Phiên Đăng nhập DirectAdmin (`da_sess_*`) & `CSRF HMAC-SHA256`:**
   * Sau khi giải mã JSON, Daemon kiểm tra tệp phiên thực tế tại `/usr/local/directadmin/data/sessions/da_sess_<session_id>` (hoặc `sess_<session_id>`), từ chối symlink, kiểm tra hạn sử dụng (`<= 24h`) và xác nhận trường `username` (hỗ trợ cả chế độ Admin đăng nhập hộ `admin|customer`) khớp tuyệt đối với chủ sở hữu `UID` đang gọi.
   * Mọi hành động thay đổi trạng thái (`IsMutatingAction(action) == true`) bắt buộc đính kèm `csrf_token` được ký `HMAC-SHA256` bởi khóa bí mật chỉ `root` đọc được tại `/var/lib/da-wptoolkit/secret/csrf.key` (`0600`).

---

## 3. Cấu trúc Khung Tin JSON Chuẩn

### 3.1. Request Envelope
```json
{
  "action": "get_bootstrap",
  "username": "reno26",
  "session_id": "a1b2c3d4e5f6g7h8i9j0",
  "csrf_token": "64_char_hex_hmac_sha256_required_for_mutating_actions",
  "instance_id": "wp_9f8a7b6c5d4e3f21",
  "job_id": "job_1122334455667788",
  "limit": 25,
  "params": {}
}
```

### 3.2. Response Envelope
```json
{
  "ok": true,
  "code": 200,
  "csrf_token": "issued_64_char_hex_hmac_sha256",
  "job_id": "job_1122334455667788",
  "data": {}
}
```
Khi xảy ra lỗi xác thực, giới hạn tần suất hoặc lỗi nghiệp vụ:
```json
{
  "ok": false,
  "code": 403,
  "error": "403 Unauthorized Peer Lineage: web/remote worker cgroup \"da-php.scope\" blocked"
}
```

---

## 4. Danh mục Action IPC (Giai đoạn 0, 1, 2, 3, 4 & 5)

### 4.1. User Socket (`/var/run/da-wptoolkit-user.sock`)
* `ping` *(Read-only)*: Kiểm tra kết nối phiên người dùng và cấp mới `csrf_token`.
* `get_bootstrap` *(Read-only)*: Trả về thông tin tài khoản, `PackagePolicy`, danh sách `domains` (Main/Addon/Subdomain + PHP version + SSL), `instances` của riêng user, `sets` và `jobs` gần nhất kèm `csrf_token`.
* `list_domains` *(Read-only)*: Liệt kê toàn bộ cấu trúc Domain/Subdomain của tài khoản DirectAdmin kèm DocumentRoot và phiên bản PHP CustomBuild tương ứng (`TC-03`).
* `list_instances` / `get_instance` *(Read-only)*: Truy vấn danh sách hoặc chi tiết 1 instance thuộc quyền sở hữu của user (trả `404` nếu khác chủ sở hữu).
* `list_plugins` / `list_themes` *(Read-only)*: Liệt kê toàn bộ Plugins hoặc Themes của 1 instance (dùng `--skip-plugins --skip-themes` an toàn ngay cả khi site bị lỗi trắng trang WSOD), đính kèm huy hiệu cảnh báo lỗ hổng **CVE** từ `vulndb`.
* `list_all_plugins` / `list_all_themes` *(Read-only)*: Gom nhóm toàn bộ Plugins/Themes xuyên suốt mọi website của user phục vụ Global Tabs (`Plugins (N)` / `Themes (N)`).
* `search_wporg` *(Read-only)*: Tìm kiếm trực tiếp kho Plugin/Theme chính thức của `api.wordpress.org` kèm kiểm tra trước cảnh báo CVE.
* `get_vulns` *(Read-only)*: Trả về báo cáo chi tiết lỗ hổng CVE của Core, Plugins và Themes trên instance.
* `get_security_status` *(Read-only)*: Kiểm tra điểm số bảo mật thực tế (`0..12`), trạng thái từng quy tắc trong **12 tiêu chí gia cố bảo mật**, loại Web Server hiện hành (`apache`/`litespeed`/`openlitespeed`/`nginx`/`nginx_apache`), chế độ **Core Integrity Shield** (`monitor`/`auto_heal`/`fortress_lock`), số tệp cách ly và danh sách ngoại lệ Whitelist.
* `list_quarantine` / `get_quarantine_diff` *(Read-only)*: Xem danh sách các tệp bị cách ly trong **Quarantine Vault** của user kèm bản xem trước `Unified Diff` an toàn (`--- a/...` / `+++ b/...`) không thực thi mã PHP.
* `list_whitelist` *(Read-only)*: Liệt kê các đường dẫn ngoại lệ Core Whitelist của 1 instance.
* `get_tools_status` *(Read-only)*: Trả về trạng thái tổng hợp của 6 thẻ công cụ Plesk Quick Tools (`SearchIndexing`, `MaintenanceMode`, `DebugConfig`, `PasswordProtection`, `DisableWPCron` + `CronIntervalMin`, `CacheKind`, `SiteTitle`, `AdminUser`, `MemoryLimit`, `DBName`, `TablePrefix`).
* `read_debug_log` *(Read-only)*: Đọc ngược `32 KB` cuối cùng của tệp `wp-content/debug.log` (kèm cờ `truncated` và kích thước tệp) không gây tràn RAM khi log lớn nhiều GB.
* `get_safe_wpconfig` *(Read-only)*: Đọc danh sách các hằng số cấu hình an toàn trong `wp-config.php` (`WP_MEMORY_LIMIT`, `WP_MAX_MEMORY_LIMIT`, `WP_POST_REVISIONS`, `AUTOSAVE_INTERVAL`, `EMPTY_TRASH_DAYS`, `FS_METHOD`, `WP_AUTO_UPDATE_CORE`) mà không để lộ thông tin nhạy cảm DB/Salts.
* `list_snapshots` / `get_snapshot_download` *(Read-only)*: Liệt kê các bản sao lưu nhanh `.tar.zst` trong `/home/<user>/wp-snapshots/<instance_id>/` hoặc xác thực quyền sở hữu đường dẫn tệp nén (hỗ trợ `stream=1` trên `plugin/user/api.php` để tải trực tiếp tệp nhị phân về trình duyệt).
* `list_sets` *(Read-only)*: Trả về 3 bộ `PluginSet` mặc định cùng các bộ riêng của user.
* `list_jobs` / `get_job` *(Read-only)*: Theo dõi tiến độ `%` của các tác vụ chạy nền.
* `scan_instances` *(Mutating - Yêu cầu POST + CSRF)*: Quét Zero-Eval toàn bộ Domain, Addon Domain, Subdomain và thư mục con (tối đa độ sâu 2) của user kèm đối chiếu nhanh lỗ hổng CVE và đồng bộ theo dõi `inotify`.
* `install_instance` *(Mutating - Yêu cầu POST + CSRF)*: Cài đặt WordPress 1-Click Express hoặc Custom vào Domain/Subdomain/Sub-path, tự động cấp phát MariaDB, sinh `wp-config.php` chuẩn bảo mật (`WP_CACHE_KEY_SALT` riêng chống trùng Redis/LSCache), tự động gia cố 6 quy tắc `critical` (nếu `AutoHardeningOnInstall=true`), đẩy vào `JobManager` và trả về thông tin đăng nhập một lần trong bộ nhớ.
* `uninstall_instance` *(Mutating - Yêu cầu POST + CSRF)*: Mở khóa an toàn Core (nếu đang bật Fortress Lock), gỡ cấu hình bảo mật Web Server, xóa bỏ WordPress an toàn (bảo toàn các thư mục Subdomain anh em và `.well-known`), tùy chọn xóa Database (`drop_db: true`).
* `sso_login` *(Mutating - Yêu cầu POST + CSRF)*: Tạo MU-Plugin tự hủy một lần (TTL `45s` + Background Reaper, chỉ lưu `SHA-256(token)`) để đăng nhập thẳng `wp-admin` không cần mật khẩu.
* `reset_admin_password` *(Mutating - Yêu cầu POST + CSRF)*: Đặt lại mật khẩu quản trị viên WordPress khẩn cấp qua `STDIN` của `wp eval`.
* `manage_plugin` / `manage_theme` *(Mutating - Yêu cầu POST + CSRF)*: Bật (`activate`), Tắt cứu hộ WSOD (`deactivate`), Xóa (`delete`), Bật/Tắt tự động cập nhật (`autoupdate_on`/`autoupdate_off`), Cài từ kho WordPress.org (`install_slug`) và Cài từ gói `.zip` đã qua bộ kiểm duyệt chống Zip-Slip/Symlink/Zip-Bomb (`install_zip`).
* `smart_update` / `bulk_smart_update` *(Mutating - Yêu cầu POST + CSRF)*: Thực thi **Smart Safe Update** đơn site hoặc hàng loạt đa site — tự động sao lưu thư mục trước cập nhật, kiểm tra sức khỏe HTTP nội bộ (`127.0.0.1`) + nhật ký lỗi PHP và **Auto-Rollback `< 3s`** khi phát hiện lỗi HTTP 500/Fatal Error (`TC-08`).
* `verify_core` *(Mutating - Yêu cầu POST + CSRF)*: Đối chiếu toàn vẹn mã băm SHA-256 của toàn bộ tệp Core WordPress với **Local Verified Core Cache**, tự động khôi phục nguyên tử (`< 50ms`) tệp Core bị sửa và rút tệp thực thi lạ trong `wp-admin`/`wp-includes` vào **Quarantine Vault** (`TC-04`).
* `set_shield_mode` / `lock_core` / `unlock_core` *(Mutating - Yêu cầu POST + CSRF)*: Chuyển đổi chế độ tự bảo vệ Core giữa `monitor`, `auto_heal` và khóa cứng mức nhân Linux `fortress_lock` (`root:<user> 0644/0755`, tuân thủ chính sách gói Hosting).
* `apply_hardening` / `revert_hardening` *(Mutating - Yêu cầu POST + CSRF)*: Áp dụng hoặc hoàn tác an toàn **12 quy tắc gia cố bảo mật WordPress** đa Web Server (`TC-07`: `.htaccess` + OpenLiteSpeed debounced graceful reload + Nginx snippet `nginx -t`).
* `restore_quarantine` / `delete_quarantine` / `manage_whitelist` *(Mutating - Yêu cầu POST + CSRF)*: Khôi phục tệp cách ly (tùy chọn thêm vào Whitelist ngoại lệ), xóa vĩnh viễn mẫu mã độc hoặc thêm/gỡ đường dẫn khỏi Core Whitelist.
* `set_search_indexing` *(Mutating - Yêu cầu POST + CSRF)*: Bật/Tắt cho phép công cụ tìm kiếm lập chỉ mục (`blog_public = 1/0`).
* `set_maintenance_mode` *(Mutating - Yêu cầu POST + CSRF)*: Bật/Tắt chế độ bảo trì trả mã `HTTP 503 Service Unavailable` kèm `Retry-After` và giao diện HTML tùy biến (không cần phụ thuộc plugin bên thứ ba).
* `set_debug_config` / `clear_debug_log` *(Mutating - Yêu cầu POST + CSRF)*: Bật/Tắt chi tiết `WP_DEBUG`, `WP_DEBUG_LOG`, `WP_DEBUG_DISPLAY`, `SCRIPT_DEBUG` và xóa rỗng an toàn `wp-content/debug.log`.
* `set_password_protection` *(Mutating - Yêu cầu POST + CSRF)*: Khóa thư mục website bằng mật khẩu `HTTP Basic Auth` đa Web Server — lưu mã băm `APR1-MD5 ($apr1$...)` tại `/home/<user>/.htpasswd/da-wptk-<id>.htpasswd` (`0640`, nằm ngoài `public_html`) và đồng bộ `.htaccess` / OpenLiteSpeed graceful reload / Nginx `auth_basic`.
* `set_wp_cron` *(Mutating - Yêu cầu POST + CSRF)*: Tắt `wp-cron.php` mặc định (`DISABLE_WP_CRON = true`) và đồng bộ tác vụ System Cron thật (`15` hoặc `30` phút) vào `/usr/local/directadmin/data/users/<user>/crontab.conf`.
* `set_caching` / `clear_cache` *(Mutating - Yêu cầu POST + CSRF)*: Bật/Tắt LiteSpeed Cache hoặc Redis Object Cache (tự động cấp `WP_CACHE_KEY_SALT` riêng) và xóa sạch bộ nhớ đệm (`wp cache flush` + `lscache` + Elementor CSS + Transients).
* `update_site_title` / `manage_admin_account` *(Mutating - Yêu cầu POST + CSRF)*: Đổi nhanh tiêu đề website (`blogname`) hoặc cập nhật email/mật khẩu/tạo mới tài khoản quản trị viên `[Setup]` (mật khẩu truyền qua `STDIN`, không lộ trên `ps aux`).
* `search_replace` / `db_maintenance` / `update_safe_wpconfig` *(Mutating - Yêu cầu POST + CSRF)*: Tìm và thay thế chuỗi/URL an toàn với dữ liệu `PHP Serialized` (hỗ trợ `dry_run` xem trước số ô thay đổi), tối ưu/sửa bảng MariaDB (`optimize`/`repair`) và cập nhật các hằng số `wp-config.php` trong danh sách cho phép.
* `create_snapshot` / `restore_snapshot` / `delete_snapshot` *(Mutating - Yêu cầu POST + CSRF)*: Đóng gói sao lưu nhanh `.tar.zst` (mã nguồn + `database.sql` + `manifest.json`, chặn Symlink Escape `TC-02`, tự động xoay vòng theo `MaxSnapshotsPerSite`), khôi phục nguyên tử 2 pha bảo toàn thư mục Subdomain anh em hoặc xóa bản sao lưu cũ.
* `clone_instance` / `sync_instance` *(Mutating - Yêu cầu POST + CSRF)*: Nhân bản 1-Click website sang Subdomain/Domain mới (`TC-09`: tự động tạo Subdomain DirectAdmin & MariaDB mới, thay thế đệ quy `PHP Serialized` + Elementor JSON URLs, xoay mới `WP_CACHE_KEY_SALT` cô lập Redis, tự động đặt `noindex` trên Staging, kiểm tra giới hạn `MaxStagingSites`) và đồng bộ 2 chiều (`files`/`db`/`both`, tự động chụp `pre_sync` Zstd Snapshot trước khi ghi đè và giữ nguyên các bảng đơn hàng/khách hàng WooCommerce đang hoạt động trên Production).
* `save_set` / `delete_set` / `apply_set` *(Mutating - Yêu cầu POST + CSRF)*: Tạo, sửa, xóa các bộ `PluginSet` cá nhân của khách hàng và áp dụng nhanh lên bất kỳ website nào.
* `detach_instance` *(Mutating - Yêu cầu POST + CSRF)*: Mở khóa Core, gỡ cấu hình bảo mật Web Server và ngắt theo dõi website khỏi danh sách quản lý mà không xóa mã nguồn hay cơ sở dữ liệu.

### 4.2. Admin Socket (`/var/run/da-wptoolkit.sock`)
* `ping` *(Read-only)*: Kiểm tra sức khỏe dịch vụ, phiên bản, thời gian Uptime, loại Web Server CustomBuild, số lượng `inotify` watches hiện tại và tổng số site đang quản lý.
* `get_overview` *(Read-only)*: Tổng hợp số liệu toàn máy chủ, số site có cảnh báo CVE / Core, hạn mức `inotify`, dung lượng **Local Verified Core Cache**, trạng thái `vulndb` và sự kiện bảo mật gần nhất.
* `get_core_cache_status` / `seed_core_cache` / `delete_core_cache`: Kiểm tra dung lượng kho đệm `/var/cache/da-wptoolkit/wp-core`, tải trước bản phát hành WordPress sạch đã xác thực MD5 từ `api.wordpress.org/core/checksums/1.0/` hoặc xóa bản đệm không còn dùng.
* `list_packages` / `save_default_policy` / `save_package_policy` / `delete_package_policy`: Tự động nhận diện danh sách gói Hosting DirectAdmin (`packages.list`), cấu hình chính sách mặc định toàn máy chủ và ghi đè hạn mức tính năng theo từng gói Hosting (`PackagePolicy`).
* `get_updater_config` / `save_updater_config` / `check_github_update`: Truy vấn trạng thái phiên bản, khóa công khai Ed25519, lưu cấu hình kênh cập nhật (`stable`/`beta`, `backup_retention`, `github_token` chỉ ghi `0600` không bao giờ trả ngược về trình duyệt) và kiểm tra bản phát hành mới trên GitHub Releases.
* `get_vulndb_status` / `sync_vulndb`: Kiểm tra trạng thái hoặc đồng bộ tức thời cơ sở dữ liệu lỗ hổng từ **Wordfence Intelligence Community Feed v2** (đọc luồng JSON tiết kiệm RAM, hỗ trợ `gzip`).
* `list_instances` *(Read-only)*: Liệt kê toàn bộ instance trên máy chủ (hỗ trợ lọc `username` và `vuln_only`).
* Toàn quyền điều phối mọi hành động của User Socket (vòng đời WordPress, Plugins/Themes, Hardening, Core Integrity Shield, **Quick Tools**, **Zstd Snapshots** và **Clone/Staging Sync**) từ CLI `da-wptoolkit` (`root`) hoặc Admin Panel.
* `backup_pre_unlock` / `backup_post_relock`: Phục vụ DirectAdmin Subdirectory Hooks (`user_backup_pre.sh` / `user_backup_post.sh`) để mở khóa tạm thời quyền sở hữu `Fortress Core Lock` trước khi DirectAdmin đóng gói sao lưu `.tar.zst` và khóa cứng lại ngay sau khi hoàn tất (`TC-06`, lưu trạng thái chống mất điện tại `backup_locks.json`).
* `cleanup_owner`: Thu hồi `inotify` watches, dọn dẹp Quarantine Vault, gỡ cấu hình Nginx snippet và xóa các bản ghi Registry khi tài khoản Hosting bị hủy (`user_destroy_post.sh`).
* `list_jobs` / `get_job` *(Read-only)*: Theo dõi hàng đợi tác vụ toàn hệ thống.
* `get_security_events` *(Read-only)*: Truy xuất nhật ký cảnh báo bảo mật (`security_events.jsonl`).
