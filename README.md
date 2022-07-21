# minimal-tls-hello-client

## 概要
[RFC8446](https://datatracker.ietf.org/doc/html/rfc8446) に準拠した「必要最低限のペイロード」を含んだ TLS1.3 ClientHello を送り、サーバーから ServerHello が送り返されたことを確認できるコードになります。

対応していない Extension などがありますが、ClientHello のエンコードとデコードの実装もされています。

## 動作確認方法

[src/main.zig](https://github.com/monkey-mas/minimal-tls-hello-client/blob/main/src/main.zig#L28-L29) ファイルで送信先サーバーの IP アドレスとポート番号を指定しています。デフォルトでは、`127.0.0.1:4443` のローカルサーバーへ ClientHello を送信します。

（送信先サーバーのアドレスとポート設定後に）トップディレクトリにて以下のコマンドを実行すると動作確認ができます。
```
zig run src/main.zig
```

サーバーから ServerHello が返答された際のログ出力例:
```
[debug] Connecting to 127.0.0.1.
[debug] Sending ClientHello...
[debug] ClientHello{ .content_type = TlsRecordContentType.handshake, .version = TlsVersion.tls_1_0, .length = 184, ...(以下省略)
[debug] Successfully received ServerHello! 
```
