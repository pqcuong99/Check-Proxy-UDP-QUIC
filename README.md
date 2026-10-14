# proxycheck — kiểm tra proxy có hỗ trợ UDP và QUIC hay không

Viết bằng Node.js **thuần** (không cần cài thêm thư viện), có cả **giao diện** (`gui.bat`) lẫn **dòng lệnh** (`proxycheck.js`). Kiểm tra:

| Cột  | Ý nghĩa |
|------|---------|
| **Loại** | Tự nhận dạng: `SOCKS5` / `HTTP` / `SOCKS4` |
| **TCP**  | `OK` = CONNECT qua proxy tới `www.cloudflare.com:443` được |
| **UDP**  | `OK` = SOCKS5 `UDP ASSOCIATE` thành công **và** gói UDP thật (truy vấn DNS tới `1.1.1.1:53` / `8.8.8.8:53`) đi qua relay có phản hồi<br>`NO` = proxy không hỗ trợ UDP (từ chối lệnh, HTTP CONNECT chỉ có TCP, SOCKS4)<br>`FAIL` = proxy *nhận* lệnh ASSOCIATE nhưng relay không chuyển được gói → **UDP "giả"**, rất hay gặp ở proxy bán trên mạng |
| **QUIC** | `OK` = tool tự dựng gói **QUIC v1 Initial thật** (TLS 1.3 ClientHello, mã hoá theo RFC 9001) gửi qua proxy tới server HTTP/3 và nhận được `ServerHello` (hoặc `Retry` / `Version Negotiation`) |

> Khác với nhiều tool chỉ xem proxy có "nhận lệnh" UDP ASSOCIATE hay không, tool này gửi gói tin thật qua relay và chờ phản hồi, nên phân biệt được proxy hỗ trợ UDP thật với proxy chỉ "giả vờ" hỗ trợ.

## Yêu cầu

- Node.js ≥ 16 (đã có sẵn trên máy: `node --version`)

## Giao diện (GUI)

```bash
node gui.js
```

hoặc double-click **`gui.bat`**. Tool mở cửa sổ ứng dụng (Edge/Chrome chế độ app, không có thanh địa chỉ)
tại `http://127.0.0.1:4780` — chỉ lắng nghe trên máy bạn, không public ra ngoài.

- **Dán danh sách** nhiều proxy (mỗi dòng 1 proxy, `ip:port:user:pass`, `ip|port|user|pass` hoặc các định dạng bên dưới)
- hoặc **nhập riêng từng ô** IP / Port / User / Pass / Loại → *Thêm vào danh sách* hoặc *Kiểm tra ngay*
- Kết quả hiện dần theo thời gian thực, bấm vào dòng để xem chi tiết từng bước
- Lọc *Chỉ UDP OK* / *Chỉ QUIC OK*, **Copy** danh sách proxy tốt, **Tải CSV / JSON**
- Đóng cửa sổ là tool tự thoát. Tuỳ chọn: `--port 0` (cổng ngẫu nhiên), `--no-open`, `--keep`

## Dòng lệnh (CLI)

```bash
# 1 proxy (tự bật chế độ chi tiết)
node proxycheck.js 1.2.3.4:1080
node proxycheck.js user:pass@1.2.3.4:1080
node proxycheck.js 1.2.3.4:1080:user:pass
node proxycheck.js "1.2.3.4|1080|user|pass"
node proxycheck.js "HTTP|proxy.example.com|10000|user|pass"

# Ép loại proxy
node proxycheck.js socks5://1.2.3.4:1080
node proxycheck.js http://user:pass@1.2.3.4:8080

# Danh sách nhiều proxy (mỗi dòng 1 proxy, dòng bắt đầu bằng # là ghi chú)
node proxycheck.js -f proxies.txt

# Lưu kết quả + lọc ra proxy dùng được
node proxycheck.js -f proxies.txt -o ketqua.csv --good udp_ok.txt --good-quic quic_ok.txt

# Chỉnh số luồng / timeout
node proxycheck.js -f proxies.txt -t 50 --timeout 8000
```

Trên Windows có thể chạy `check.bat proxies.txt` (hoặc kéo-thả file danh sách vào `check.bat`).

### Định dạng proxy được hỗ trợ

```
host:port
host:port:user:pass
host|port
host|port|user|pass
HTTP|host|port|user|pass
SOCKS5|host|port|user|pass
SOCKS4|host|port|user|pass
user:pass:host:port
user:pass@host:port
socks5://...   socks4://...   http://...   (tiền tố ép loại, không có thì tự nhận dạng)
```

Loại proxy đứng đầu dạng dấu `|` không phân biệt chữ hoa/thường. Nếu không có user/pass, có thể nhập `HTTP|host|port`.

Khi nhập proxy có dấu `|` trên dòng lệnh, đặt toàn bộ proxy trong dấu nháy, ví dụ `"1.2.3.4|1080|user|pass"`.

### Tuỳ chọn

```
-f, --file FILE       File danh sách proxy
-t, --threads N       Số proxy kiểm tra đồng thời (mặc định 20)
--timeout MS          Timeout mỗi bước, ms (mặc định 5000)
--type socks5|http|socks4   Ép loại proxy cho tất cả
-o, --output FILE     Ghi kết quả đầy đủ ra .json hoặc .csv
--good FILE           Ghi các proxy hỗ trợ UDP (mỗi dòng 1 proxy)
--good-quic FILE      Ghi các proxy chạy được QUIC
--dns IP[,IP]         DNS server dùng test UDP (mặc định 1.1.1.1,8.8.8.8)
--quic-host H[,H]     Server HTTP/3 dùng test QUIC (mặc định www.cloudflare.com,www.google.com)
--no-quic             Bỏ qua test QUIC
-v, --verbose         In chi tiết từng bước
--no-color            Không tô màu
```

## Ví dụ kết quả

```
#     Proxy                   Loại    TCP   UDP   QUIC  ms
1/4   1.2.3.4:1080            SOCKS5  OK    OK    OK    120
      xác thực : none
      TCP      : CONNECT www.cloudflare.com:443 OK
      UDP      : DNS 1.1.1.1:53 trả lời sau 131ms (www.cloudflare.com -> 104.16.124.96) qua relay 1.2.3.4:1080
      QUIC     : www.cloudflare.com (104.16.124.96:443): QUIC v1 ServerHello sau 140ms
2/4   5.6.7.8:1080            SOCKS5  OK    NO    NO    95
      UDP      : UDP ASSOCIATE bị từ chối: command not supported (rep=7)
3/4   9.9.9.9:1080            SOCKS5  OK    FAIL  FAIL  88
      UDP      : UDP ASSOCIATE OK (0.0.0.0:40001) nhưng relay không chuyển được gói UDP
4/4   8.8.4.4:3128            HTTP    OK    NO    NO    70
      UDP      : HTTP proxy chỉ có CONNECT (TCP); connect-udp trả về 400
```

## Cách hoạt động (chi tiết kỹ thuật)

1. **Nhận dạng**: mở kết nối TCP, thử handshake SOCKS5 và HTTP CONNECT song song, sau đó SOCKS4.
2. **UDP (SOCKS5)**: gửi lệnh `UDP ASSOCIATE` (RFC 1928). Nếu proxy chấp nhận, gửi truy vấn DNS thật
   qua địa chỉ relay proxy trả về (tự động thay bằng IP proxy nếu proxy trả `0.0.0.0` / IP nội bộ).
   Nhận được trả lời DNS = UDP hoạt động thật.
3. **UDP (HTTP)**: HTTP proxy thường chỉ có `CONNECT` (TCP). Tool thử thêm MASQUE `connect-udp`
   (RFC 9298) qua `Upgrade: connect-udp`; gần như không proxy thương mại nào hỗ trợ.
4. **QUIC**: dựng gói QUIC v1 Initial 1200 byte đúng chuẩn RFC 9000/9001 — sinh khoá Initial bằng
   HKDF, mã hoá AES-128-GCM, header protection — chứa TLS 1.3 ClientHello (ALPN `h3`), gửi tới
   `www.cloudflare.com:443` qua relay. Giải mã gói Initial của server trả về:
   - `ServerHello` → QUIC chạy hoàn toàn bình thường qua proxy
   - `Retry` / `Version Negotiation` → gói QUIC vẫn đi qua được
   - Không có phản hồi → proxy chặn UDP tới cổng 443 (hoặc chặn QUIC)

## Test không cần proxy thật

```bash
node test/fake_proxies.js                      # cửa sổ 1: dựng 6 proxy giả lập trên 127.0.0.1
node proxycheck.js -f test/test_proxies.txt -v # cửa sổ 2
```

## Dùng như thư viện

```js
const { parseProxy, checkProxy, DEFAULTS } = require('./proxycheck');
const r = await checkProxy(parseProxy('user:pass@1.2.3.4:1080'), { ...DEFAULTS, timeout: 5000 });
console.log(r.udp, r.quic, r.udp_detail, r.quic_detail);
```
"# Check-Proxy-UDP-QUIC" 
