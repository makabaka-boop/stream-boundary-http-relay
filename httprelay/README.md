# httprelay — HTTP/1.1 TCP 反向代理（仅 GET/POST）

固定上游地址的反向代理，自行解析 HTTP/1.1 起始行、CRLF 头部以及
`Content-Length` / `Transfer-Encoding: chunked` 两种正文分帧，不使用
`net/http` 的服务端解析，也不支持 TLS、Upgrade 或 CONNECT。

## 运行

```
go run ./cmd/httprelay -listen 127.0.0.1:8080 -upstream 127.0.0.1:9000
```

## 关键语义

- 每条下游 TCP 连接独占绑定一条上游 TCP 连接；合法的流水线请求严格
  按序转发，响应按序返回。
- 请求正文以 4 KiB 固定缓冲流式搬运，绝不整份缓冲；**单请求正文硬上限
  32 KiB**。定长请求超限在连接上游前直接回 `413`；chunked 请求的超限
  在解码过程中中止。
- 一律拒绝并关闭连接（不做模糊兼容）：
  - 重复 `Content-Length`（即使数值相同）；
  - 同时出现 `Content-Length` 与 `Transfer-Encoding`；
  - 折叠头（obs-fold）、裸 LF、畸形起始行/字段名；
  - 非 `chunked` 的 TE、GET/POST 以外的方法；
  - 非法十六进制块大小、块数据/尾部截断等非法分块。
- 转发时剔除全部逐跳头（`Connection`、`Keep-Alive`、`TE`、
  `Transfer-Encoding`、`Upgrade`、`Proxy-Connection`、
  `Proxy-Authorization`、`Proxy-Authenticate`、`Trailer`）以及
  `Connection` 头逐字段点名的头；`Expect: 100-continue` 由代理就地处理
  后剔除。
- 上游请求的长度编码由代理重新生成，`Content-Length` 与
  `Transfer-Encoding` 恰好出现一种（chunked 输入重编码为规范分块）。
- 以下任一情况发生后，**两端连接都立即作废关闭，排队请求不再转发**：
  下游取消、请求正文半途断开、正文超限/分块非法、上游无响应/响应头畸形、
  上游响应正文截断。事件通过日志和 `Proxy.IncompleteEvents()` 记录，
  其中 `Forwarded > 0` 表示源站已收到部分请求字节——代理不会、也无法
  承诺撤回源站可能已产生的副作用。

## 测试

测试使用真实 TCP 源站（同样自行严格解析），以逐字节、随机小分块方式
送入报文，并核对源站实际收到的请求边界与正文 SHA-256 摘要；覆盖慢读、
长度混淆、流水线串流防护、下游取消、定长/分块响应截断等场景。

```
go test -race ./...
```
