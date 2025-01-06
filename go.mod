module github.com/sagernet/sing-box

replace (
	github.com/mattn/go-ieproxy => github.com/fanyiguang/go-ieproxy v0.0.0-20231120070622-b1a78033a014
	github.com/sagernet/gvisor => github.com/sagernet/gvisor v0.0.0-20230627031050-1ab0276e0dd2
	github.com/sagernet/sing => github.com/fanyiguang/sing v0.2.5-0.20240911030018-c447ef6045a3
	github.com/sagernet/sing-shadowsocks v0.2.6 => github.com/fanyiguang/sing-shadowsocks v0.0.0-20240201085418-a2ff46dbc119
	github.com/sagernet/sing-shadowsocks2 v0.2.0 => github.com/fanyiguang/sing-shadowsocks2 v0.2.1-0.20240319095538-2633709b1dac
	github.com/sagernet/sing-tun => github.com/sagernet/sing-tun v0.1.16
	github.com/sagernet/utls v1.5.4 => github.com/fanyiguang/utls v1.5.5-0.20250106060502-2a3a0a4a2844
)

go 1.20

require (
	berty.tech/go-libtor v1.0.385
	github.com/caddyserver/certmagic v0.20.0
	github.com/cloudflare/circl v1.3.7
	github.com/cretz/bine v0.2.0
	github.com/darren/gpac v0.0.0-20210609082804-b56d6523a3af
	github.com/fanyiguang/brick v0.0.0-20241206101325-13f7620737d7
	github.com/fsnotify/fsnotify v1.7.0
	github.com/go-chi/chi/v5 v5.0.11
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.3
	github.com/gofrs/uuid/v5 v5.0.0
	github.com/insomniacslk/dhcp v0.0.0-20231206064809-8c70d406f6d2
	github.com/libdns/alidns v1.0.3
	github.com/libdns/cloudflare v0.1.0
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mattn/go-ieproxy v0.0.11
	github.com/mholt/acmez v1.2.0
	github.com/miekg/dns v1.1.57
	github.com/ooni/go-libtor v1.1.8
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/sagernet/bbolt v0.0.0-20231014093535-ea5cb2fe9f0a
	github.com/sagernet/cloudflare-tls v0.0.0-20231208171750-a4483c1b7cd1
	github.com/sagernet/gomobile v0.1.1
	github.com/sagernet/gvisor v0.0.0-20231209105102-8d27a30e436e
	github.com/sagernet/quic-go v0.40.1-beta.2
	github.com/sagernet/reality v0.0.0-20230406110435-ee17307e7691
	github.com/sagernet/sing v0.3.0
	github.com/sagernet/sing-dns v0.1.12
	github.com/sagernet/sing-mux v0.2.0
	github.com/sagernet/sing-quic v0.1.7
	github.com/sagernet/sing-shadowsocks v0.2.6
	github.com/sagernet/sing-shadowsocks2 v0.2.0
	github.com/sagernet/sing-shadowtls v0.1.4
	github.com/sagernet/sing-tun v0.2.0
	github.com/sagernet/sing-vmess v0.1.8
	github.com/sagernet/smux v0.0.0-20231208180855-7041f6ea79e7
	github.com/sagernet/tfo-go v0.0.0-20231209031829-7b5343ac1dc6
	github.com/sagernet/utls v1.5.4
	github.com/sagernet/wireguard-go v0.0.0-20231215174105-89dec3b2f3e8
	github.com/sagernet/ws v0.0.0-20231204124109-acfe8907c854
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/spf13/cobra v1.8.0
	github.com/stretchr/testify v1.9.0
	go.uber.org/zap v1.26.0
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.18.0
	golang.org/x/net v0.20.0
	golang.org/x/sync v0.5.0
	golang.org/x/sys v0.19.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
	google.golang.org/grpc v1.60.1
	google.golang.org/protobuf v1.32.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	howett.net/plist v1.0.1
)

//replace github.com/sagernet/sing => ../sing

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dlclark/regexp2 v1.4.1-0.20201116162257-a2a8dda75c91 // indirect
	github.com/dop251/goja v0.0.0-20210427212725-462d53687b0d // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20231101202521-4ca4178f5c7a // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/onsi/ginkgo/v2 v2.9.7 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-20 v0.4.1 // indirect
	github.com/sagernet/go-tun2socks v1.16.12-0.20220818015926-16cb67876a61 // indirect
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97 // indirect
	github.com/scjalliance/comshim v0.0.0-20230315213746-5e51f40bd3b9 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tklauser/go-sysconf v0.3.13 // indirect
	github.com/tklauser/numcpus v0.7.0 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231002182017-d307bd883b97 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)
