<div align="center">
  <img src="./plugin/images/user_icon.svg" alt="DA WordPress Toolkits" width="76" height="76" />
  <h1>DA-WordPressToolkits</h1>
  <p><strong>Bộ Công Cụ Quản Trị Vòng Đời, Bảo Mật Đa Tầng &amp; Tự Phục Hồi WordPress cho DirectAdmin</strong></p>

  <p>
    <a href="https://github.com/shostwp-byte/da-wordpresstoolkit/actions/workflows/ci.yml"><img src="https://github.com/shostwp-byte/da-wordpresstoolkit/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
    <img src="https://img.shields.io/badge/version-v0.6.0-4f46e5" alt="Version v0.6.0" />
    <img src="https://img.shields.io/badge/Go-1.22%2B%20(CGO__ENABLED%3D0)-00ADD8?logo=go&logoColor=white" alt="Pure Go 1.22+" />
    <img src="https://img.shields.io/badge/dependencies-0%20external-10b981" alt="Zero External Dependencies" />
    <img src="https://img.shields.io/badge/DirectAdmin-Evolution%20Skin-2563eb" alt="DirectAdmin Evolution Skin" />
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-slate" alt="MIT License" /></a>
  </p>
</div>

---

**DA-WordPressToolkits** (`da_wp_toolkits`) là giải pháp quản trị WordPress gốc (**Native Linux Daemon + DirectAdmin Evolution Skin Plugin**) viết hoàn toàn bằng **Golang chuẩn (`CGO_ENABLED=0`, 0 thư viện ngoài trong `go.mod`)**, được thiết kế chuyên biệt cho nhà cung cấp Shared/Cloud Hosting và người dùng cuối với trải nghiệm tương đương **Plesk WordPress Toolkit**.

<div align="center">
  <img src="./plan/assets/ui_reference_wptoolkit.png" alt="Giao diện WordPress Manager trên DirectAdmin Evolution Skin" width="920" />
</div>

---

## Điểm Khác Biệt Cốt Lõi

- **Kiến trúc Siêu Nhẹ & Tự Chủ 100%:** Biên dịch thành một tệp thực thi tĩnh duy nhất (`~8.6 MB` trên `linux/amd64`, `~7.9 MB` trên `linux/arm64`), tiêu thụ `< 20 MB RAM` ở trạng thái nghỉ, không cần Node.js/Python/SQLite hay bất kỳ runtime phụ trợ nào trên máy chủ DirectAdmin.
- **Trải Nghiệm End-User Chuẩn Plesk WordPress Toolkit:** Quản lý tập trung toàn bộ website WordPress trên **Tên miền chính**, **Addon Domain**, **Subdomain** và **Thư mục con**; hỗ trợ **Dark Mode**, song ngữ **Việt / Anh**, 3 chế độ hiển thị (*Cards / Grid / Compact List*) và thời gian phản hồi giao diện `< 50ms`.
- **Tự Bảo Vệ & Phục Hồi Tức Thời (`Core Integrity Shield`):** Giám sát thời gian thực thư mục nhân WordPress qua `Linux inotify`, tự động cách ly mã độc/webshell lạ vào **Quarantine Vault** (kèm trình xem **Unified Diff**) và khôi phục tệp gốc từ **Local Verified Core Cache** trong `< 50ms`, hoặc khóa cứng mức hệ điều hành với **Fortress Core Lock (`root:<user>`)**.
- **Cập Nhật An Toàn Tự Hoàn Tác (`Smart Safe Update`):** Tự động sao lưu trước khi nâng cấp Plugins/Themes/Core, kiểm tra sức khỏe HTTP loopback sau cập nhật và **tự động Rollback dưới 3 giây** nếu phát hiện lỗi `HTTP 500` / PHP Fatal Error (WSOD).
- **Bảo Mật IPC 3 Lớp Chống Giả Mạo Từ Webshell:** Tách biệt hoàn toàn Unix Socket của Admin và End-User, xác thực đồng thời `SO_PEERCRED` mức nhân Linux, phả hệ tiến trình `/proc/<pid>` của DirectAdmin (chặn đứng PHP-FPM/LSPHP webshell trên cùng UID khách hàng) và phiên `da_sess_*` + `HMAC-SHA256 CSRF`.

---

## Tổng Hợp Tính Năng

| Phân hệ | Tính năng chi tiết |
| :--- | :--- |
| **Quản lý Vòng đời & SSO** | Tự động quét phát hiện WordPress không thực thi PHP (`Zero-Eval Discovery`, 200 site `< 1.5s`), cài đặt **1-Click Express/Custom** từ kho đệm nội bộ, **Đăng nhập 1-Click SSO** tự hủy sau 45 giây không để lại plugin rác, gỡ cài đặt an toàn bảo toàn Subdomain anh em. |
| **Plugins, Themes & Sets** | Bật/tắt/cập nhật/xóa đơn lẻ hoặc hàng loạt đa site (luôn kèm `--skip-plugins --skip-themes` để cứu hộ cả khi web đang lỗi trắng trang), tìm kiếm trực tiếp kho **WordPress.org**, tải lên gói `.zip` phân mảnh tới **64 MB** có kiểm duyệt Zip-Slip, tạo **Sets** cài nhanh bộ công cụ mẫu. |
| **Smart Safe Update & CVE** | Sao lưu vi mô trước khi cập nhật, kiểm tra phản hồi HTTP thực tế và hoàn tác tự động nếu phát sinh lỗi 500; tích hợp luồng cảnh báo lỗ hổng **Wordfence Community CVE Feed** miễn phí không cần API key trả phí. |
| **Core Integrity Shield** | 3 chế độ bảo vệ (*Monitor*, *Auto-Heal `< 50ms`*, *Fortress Core Lock `root:<user>`*), **Anti-Thrashing Guard** tự nâng cấp lên khóa pháo đài khi bị ghi đè lặp lại, **Quarantine Vault** xem đối chiếu mã độc Unified Diff, tự động mở/khóa khi chạy **DirectAdmin Backup Hooks**. |
| **Đa Web Server Hardening** | Bộ **12 quy tắc gia cố bảo mật** một chạm, tự động sinh cấu hình chuẩn xác cho **Apache**, **LiteSpeed Enterprise**, **OpenLiteSpeed** (tự gom lệnh graceful reload chống nghẽn) và **Nginx Standalone** (kiểm tra `nginx -t` trước khi áp dụng). |
| **Plesk Quick Tools** | Công tắc bật/tắt nhanh: *Search Engine Indexing*, *Caching (LSCache / Redis Object Cache cô lập `WP_CACHE_KEY_SALT`)*, *Maintenance Mode 503 tùy biến*, *Debugging (`WP_DEBUG` + trình đọc ngược 32 KB cuối `debug.log`)*, *HTTP Basic Auth `.htpasswd` ngoài `public_html`*, *Tiếp quản `wp-cron.php` sang System Cron DirectAdmin*. |
| **Clone, Staging & Sync** | Nhân bản 1-Click sang Domain/Subdomain mới, tự động gắn `noindex` cho môi trường Staging, thay thế URL an toàn cho dữ liệu **PHP Serialized** & **Elementor JSON** (có xem trước *Dry-Run*), đồng bộ 2 chiều Staging ⇄ Production **bảo toàn đơn hàng & khách hàng WooCommerce**. |
| **Zstd Snapshots & DB** | Sao lưu & khôi phục toàn phần (Mã nguồn + Database `.sql`) nén chuẩn **Zstandard (`.tar.zst` RFC 8878)** tính vào đúng hạn mức dung lượng người dùng, tải trực tiếp về máy tính, tự động xoay vòng bản cũ; tối ưu/sửa bảng DB và chỉnh sửa an toàn hằng số `wp-config.php`. |
| **Server Admin Console** | Giao diện quản trị 4 Tab cho nhà cung cấp Hosting: *Tổng quan toàn máy chủ & Nhật ký sự kiện bảo mật*, *Chính sách giới hạn theo từng Hosting Package & Global Sets*, *Quản lý Core Cache & CSDL CVE*, *Cập nhật tự động từ GitHub Releases xác thực chữ ký số Ed25519*. |

---

## Kiến Trúc Hệ Thống & Bảo Mật 3 Lớp

```mermaid
flowchart LR
    subgraph Browser["Trình duyệt (Evolution Skin)"]
        UserUI["End-User SPA<br/>plugin/user/index.html"]
        AdminUI["Admin Console<br/>plugin/admin/index.html"]
    end

    subgraph DirectAdmin["DirectAdmin CGI Sandbox"]
        UserRelay["user/api.raw + api.php<br/>(Chạy dưới UID khách hàng)"]
        AdminRelay["admin/api.raw + api.php<br/>(Chạy dưới quyền Admin)"]
    end

    subgraph Daemon["da-wptoolkitd (Root Go Service)"]
        Guard["Auth Guard 3 Lớp<br/>1. SO_PEERCRED (UID/PID)<br/>2. /proc Lineage & Cgroup<br/>3. da_sess_* + HMAC CSRF"]
        CoreEngine["Core Modules<br/>Discovery | Lifecycle | SmartUpdate<br/>CoreShield (inotify) | Hardening<br/>QuickTools | CloneSync | Snapshot"]
        WPCLI["Sandboxed WP-CLI Runner<br/>setuid(user) + nice/ionice + timeout"]
    end

    UserUI -->|HTTPS Same-Origin + CSRF| UserRelay
    AdminUI -->|HTTPS Same-Origin + CSRF| AdminRelay
    UserRelay -->|/var/run/da-wptoolkit-user.sock| Guard
    AdminRelay -->|/var/run/da-wptoolkit.sock| Guard
    Guard --> CoreEngine
    CoreEngine --> WPCLI
```

### Nguyên tắc An toàn Bất biến (Security Invariants)

1. **Không bao giờ thực thi WP-CLI dưới quyền `root`:** Mọi tiến trình `wp-cli`, giải nén hay thao tác tệp trong không gian người dùng đều hạ quyền xuống đúng `UID/GID` của tài khoản DirectAdmin thông qua `SysProcAttr.Credential` kết hợp giới hạn tài nguyên `nice` / `ionice` và timeout cứng.
2. **Chống leo thang đặc quyền qua Symlink (`internal/fsguard`):** Kiểm tra từng chặng đường dẫn (component-by-component `Lstat`), từ chối mọi symlink trỏ ra ngoài `/home/<user>/domains` trước khi đọc, ghi, sao lưu hoặc xóa.
3. **Không rò rỉ thông tin nhạy cảm trên Command-Line (`ps aux`):** Mật khẩu quản trị WordPress, thông tin kết nối MariaDB (`--defaults-extra-file` `0600`) và `GitHubToken` không bao giờ truyền qua tham số dòng lệnh hay trả ngược về giao diện.

---

## Cấu Trúc Thư Mục Dự Án

```text
DA-WordPressToolkits/
├── cmd/da-wptoolkit/         # Điểm vào CLI quản trị & tiến trình nền da-wptoolkitd
├── internal/
│   ├── auth/                 # Xác thực IPC 3 lớp (SO_PEERCRED, /proc lineage, da_sess_*, HMAC CSRF)
│   ├── clonesync/            # Nhân bản Staging, PHP Serialized Search-Replace & Đồng bộ WooCommerce
│   ├── config/               # Quản lý chính sách theo Hosting Package & cấu hình GitHub Updater
│   ├── dadomains/            # Phân giải Domain, Addon Domain, Subdomain & SSL từ DirectAdmin
│   ├── daemon/               # Điều phối dịch vụ IPC, Job Queue & Admin/User Handlers
│   ├── daphp/                # Ánh xạ phiên bản PHP CustomBuild trên từng tên miền
│   ├── database/             # Cấp phát MySQL/MariaDB tương thích DirectAdmin 1.670+
│   ├── dausers/              # Đọc thông tin tài khoản, UID/GID & Hosting Package DirectAdmin
│   ├── discovery/            # Quét phát hiện WordPress tĩnh tốc độ cao (Zero-Eval PHP)
│   ├── extensions/           # Quản lý Plugins, Themes, Sets & kiểm duyệt gói .zip
│   ├── fsguard/              # Lá chắn chống tấn công Symlink Escape & TOCTOU
│   ├── hardening/            # Engine 12 quy tắc gia cố bảo mật WordPress
│   ├── integrity/            # Core Integrity Shield (inotify, Quarantine Diff, Fortress Lock)
│   ├── ipc/                  # Máy chủ/máy khách Dual Unix Domain Socket giới hạn khung 64 KB
│   ├── lifecycle/            # Cài đặt 1-Click từ Core Cache, Ephemeral SSO 45s & Gỡ cài đặt
│   ├── quicktools/           # Maintenance, WP_DEBUG Tail, Basic Auth, Cron, Cache & wp-config
│   ├── smartupdate/          # Cập nhật thông minh kèm kiểm tra HTTP & hoàn tác tự động < 3s
│   ├── snapshot/             # Nén & giải nén bản sao lưu Zstandard (.tar.zst RFC 8878)
│   ├── store/                # Kho lưu trữ JSON nguyên tử (Atomic Write) & Nhật ký bảo mật
│   ├── version/              # Định danh phiên bản & khóa công khai Ed25519 xác thực bản phát hành
│   ├── vulndb/               # Đồng bộ & đối chiếu cơ sở dữ liệu lỗ hổng Wordfence CVE
│   ├── webserver/            # Bộ điều hợp cấu hình Apache, LiteSpeed, OpenLiteSpeed & Nginx
│   └── wpcli/                # Trình chạy WP-CLI hạ quyền UID/GID kèm kiểm soát I/O
├── plugin/                   # Gói tích hợp DirectAdmin Evolution Skin
│   ├── admin/                # Bảng điều khiển Server Admin (4 Tabs) & cầu nối IPC api.php
│   ├── user/                 # Giao diện WordPress Manager cho End-User & Chunked Upload api.php
│   ├── hooks/                # Điểm gắn menu & biểu tượng trên DirectAdmin Evolution Skin
│   ├── images/               # Biểu tượng vector SVG cho User & Admin
│   └── plugin.conf           # Khai báo metadata plugin DirectAdmin
├── scripts/                  # Kịch bản kiểm thử nghiệm thu (qa_verify.sh) & DirectAdmin Backup Hooks
├── systemd/                  # Cấu hình dịch vụ hệ thống da-wptoolkitd.service
└── docs/                     # Tài liệu đặc tả giao thức IPC & kiến trúc bảo mật
```

---

## Yêu Cầu Hệ Thống

- **Hệ điều hành:** CloudLinux 8/9, AlmaLinux 8/9, Rocky Linux 8/9, Ubuntu 20.04/22.04/24.04 hoặc Debian 11/12 (`x86_64` / `amd64` và `aarch64` / `arm64`).
- **Control Panel:** DirectAdmin `1.670+` sử dụng giao diện **Evolution Skin**.
- **Web Server hỗ trợ:** OpenLiteSpeed, LiteSpeed Enterprise, Apache (`mod_ruid2` / `PHP-FPM`) hoặc Nginx Standalone / Reverse Proxy.
- **Cơ sở dữ liệu & Công cụ:** MySQL `8.0+` hoặc MariaDB `10.4+` – `11.x`, PHP CLI (CustomBuild) và `wp-cli` (`/usr/local/bin/wp`).

---

## Hướng Dẫn Biên Dịch & Kiểm Thử Từ Mã Nguồn

### 1. Yêu cầu môi trường phát triển

- **Go `1.22+`** (biên dịch hoàn toàn với `CGO_ENABLED=0`, không cần trình biên dịch C).

### 2. Biên dịch nhị phân tĩnh cho máy chủ Linux

```bash
# Kiểm tra định dạng, phân tích tĩnh (go vet), chạy toàn bộ Unit Test và biên dịch
make all

# Biên dịch chéo nhị phân tĩnh cho Linux x86_64 (dist/da-wptoolkit-linux-amd64)
make build-linux-amd64

# Biên dịch chéo nhị phân tĩnh cho Linux ARM64 (dist/da-wptoolkit-linux-arm64)
make build-linux-arm64
```

### 3. Chạy bộ kiểm thử tự động

```bash
# Chạy toàn bộ 22 package kiểm thử tích hợp & bảo mật
CGO_ENABLED=0 go test -v -race ./...

# Trên máy chủ DirectAdmin thực tế: kiểm tra trạng thái socket, daemon và hooks
bash scripts/qa_verify.sh preflight
```

### 4. Một số lệnh quản trị CLI tiêu biểu (`da-wptoolkit`)

```bash
# Kiểm tra phiên bản và kết nối tới tiến trình nền da-wptoolkitd
da-wptoolkit version
da-wptoolkit ping

# Quét tự động toàn bộ website WordPress trên máy chủ
da-wptoolkit scan --all

# Liệt kê danh sách các website WordPress (hoặc lọc riêng các site có cảnh báo CVE)
da-wptoolkit list
da-wptoolkit list --vuln

# Kiểm tra tính toàn vẹn nhân WordPress và đồng bộ dữ liệu lỗ hổng CVE
da-wptoolkit verify-core --all
da-wptoolkit sync-vulndb
```

---

## Lộ Trình Phát Triển (Roadmap)

- [x] **Giai đoạn 0 (`v0.1.0`):** Kiến trúc Monorepo, Kho lưu trữ nguyên tử `internal/store`, Hàng đợi tác vụ nền `JobManager`, Bảo mật IPC 3 lớp và khung CI/CD đa kiến trúc.
- [x] **Giai đoạn 1 (`v0.2.0`):** Bộ phân giải Domain/PHP DirectAdmin, lá chắn chống Symlink `fsguard`, Zero-Eval Auto-Discovery, Sandboxed WP-CLI, cấp phát Database & 1-Click Installer + Ephemeral SSO.
- [x] **Giai đoạn 2 (`v0.3.0`):** Quản lý tập trung Plugins/Themes/Sets đơn site & đa site, cứu hộ WSOD, **Smart Safe Update** tự hoàn tác `< 3s` & cảnh báo lỗ hổng **Wordfence CVE Feed**.
- [x] **Giai đoạn 3 (`v0.4.0`):** Bộ điều hợp Đa Web Server (Apache/LiteSpeed/OpenLiteSpeed/Nginx), 12 quy tắc gia cố bảo mật & **Core Integrity Shield** (`inotify` Auto-Heal + Quarantine Diff + Fortress Core Lock + Backup Hooks).
- [x] **Giai đoạn 4 (`v0.5.0`):** Bộ công cụ **Plesk Quick Tools**, sao lưu nén **Zstd Snapshots (`.tar.zst`)** & nhân bản **Clone / Staging / Bidirectional Sync** bảo toàn đơn hàng WooCommerce.
- [x] **Giai đoạn 5 (`v0.6.0`):** Hoàn thiện giao diện **End-User WordPress Manager SPA** (Indigo/Slate, Dark Mode, VI/EN, Chunked `.zip` Upload 64 MB) & **Server Admin Console 4 Tabs** trên Evolution Skin.
- [ ] **Giai đoạn 6 (`v1.0.0`):** DirectAdmin Lifecycle Event Hooks tự động hóa theo sự kiện tạo/xóa User & Domain, hoàn thiện thực thi cập nhật tự động xác thực chữ ký số Ed25519, Stress Test tải cao & đóng gói gói cài đặt `da-wptoolkit.tar.gz`.

---

## Tài Liệu Kỹ Thuật

- [Đặc Tả Giao Thức IPC & Xác Thực 3 Lớp (`docs/IPC_PROTOCOL.md`)](./docs/IPC_PROTOCOL.md)
- [Đặc Tả Kỹ Thuật & Kế Hoạch Phát Triển Chi Tiết](./plan/Đặc%20Tả%20Kỹ%20Thuật%20&%20Kế%20Hoạch%20Phát%20Triển%20DA-WordPressToolkits.md)

---

## Giấy Phép (License)

Phát hành theo giấy phép [MIT License](./LICENSE) — Bản quyền © 2026 **CÔNG TY CỔ PHẦN W2W (SHOST)**.
